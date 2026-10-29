import {LitElement, css, html, nothing} from 'lit';
import {customElement, property, state} from 'lit/decorators.js';
import {ApiConfigClient} from './api/config-client';
import {
  DraftClient,
  draftOperationCount,
  type DraftChange,
  type DraftCommit,
  type DraftCreateOperation,
  type DraftDeleteOperation,
  type DraftPreflight,
  type DraftScalar,
  type DraftSnapshot,
  type DraftValidation,
} from './api/draft-client';
import {FakeConfigClient} from './api/fake-client';
import type {
  AddressObject,
  CaptureSettings,
  ConfigScalar,
  ConfigSnapshot,
  ConfigValue,
  ConfigUsage,
  DebugSettings,
  PolicySummary,
  PortObject,
  ProfileObject,
  ProtocolObject,
  SystemSettings,
} from './api/models';
import {
  SystemClient,
  type AlertSnapshot,
  type AuditSnapshot,
  type EventSnapshot,
  type GatewaySession,
  type InterfaceSnapshot,
  type JobSnapshot,
  type NeighborSnapshot,
  type RuntimeMetricsSnapshot,
  type SessionActivitySnapshot,
  type SmithproxyState,
  type SystemCapabilities,
  type TlsCacheSnapshot,
  type TransactionCapabilityState,
} from './api/system-client';
import {readRuntimeConfig, type RuntimeConfig} from './config/runtime-config';
import {persistentConfigurationValues} from './config/persistent-values';
import {
  buildDiagnosticsReport,
  serializeDiagnosticsReport,
  type GatewayDiagnosticState,
} from './diagnostics/report';
import {classifyFreshness, freshnessLabel, type FreshnessState} from './monitoring/freshness';
import {probeIncidents} from './monitoring/incidents';
import {drawerRouteSearch, parseDrawerRoute} from './state/drawer-route';
import {DrawerStore, MAXIMUM_DRAWER_DEPTH, type DrawerEntry} from './state/drawer-store';
import {
  connectingSystemStatus,
  displayState,
  statusFromFailure,
  statusFromSnapshot,
  statusTone,
  type SystemStatus,
} from './state/system-status';

const navigation = ['Dashboard', 'Network', 'Objects', 'Policy', 'Monitoring', 'Logs', 'System'];
type EventStreamState = 'connecting' | 'live' | 'paused' | 'invalid' | 'unavailable';
type CapabilityBootstrapState = 'discovering' | 'refreshing' | 'ready' | 'unavailable';
type EventCategoryFilter = 'all' | 'control-plane' | 'backend-job';
type StatusTone = 'success' | 'warning' | 'danger';

interface CollectorPresentation {
  label: string;
  tone: StatusTone;
  current: boolean;
  reportedReady: boolean;
}

const systemBooleanFields = [
  ['accept_tproxy', 'accept-tproxy'], ['accept_redirect', 'accept-redirect'],
  ['accept_socks', 'accept-socks'], ['accept_http_connect', 'accept-http-connect'],
  ['accept_api', 'accept-api'],
  ['extended_local_destination_protection', 'extended-local-destination-protection'],
  ['policy_fail_open', 'policy-fail-open'],
  ['policy_access_request_fail_open', 'access-fail-open'],
  ['ssl_autodetect', 'tls-autodetect'], ['ssl_autodetect_harder', 'tls-autodetect-harder'],
  ['ssl_use_ktls', 'kernel-tls'], ['http_api.key_extend_on_access', 'api-key-extend'],
  ['http_api.loopback_only', 'api-loopback'],
  ['http_api.pam_login', 'api-pam'], ['http_api.allow_api_header', 'api-header'],
  ['webhook.enabled', 'webhook-enabled'], ['webhook.tls_verify', 'webhook-tls'],
  ['webhook.sift', 'webhook-sift'], ['webhook.api_override', 'webhook-override'],
  ['webhook.sift_lored_include_url', 'webhook-sift-lored-include-url'],
  ['webhook.task_debug', 'webhook-task-debug'],
  ['webhook.task_debug_dump', 'webhook-task-debug-dump'],
  ['default_write_payload', 'logging-default-payload'], ['log_console', 'logging-console'],
  ['tpool_log', 'aux-thread-pool-log'], ['socks.async_dns', 'aux-socks-async-dns'],
  ['socks.ipver_mixing', 'aux-socks-ipver-mixing'],
  ['socks.prefer_ipv6', 'aux-socks-prefer-ipv6'],
] as const;

const systemWorkerFields = [
  ['plaintext_workers', 'plaintext'], ['ssl_workers', 'tls'], ['udp_workers', 'udp'],
  ['dtls_workers', 'dtls'], ['quic_workers', 'quic'], ['socks_workers', 'socks'],
  ['http_connect_workers', 'http-connect'],
] as const;

const systemNumericFields = [
  ['plaintext_port', 'port-plaintext', 65535], ['ssl_port', 'port-tls', 65535],
  ['udp_port', 'port-udp', 65535], ['quic_port', 'port-quic', 65535],
  ['dtls_port', 'port-dtls', 65535], ['socks_port', 'port-socks', 65535],
  ['http_connect_port', 'port-http-connect', 65535],
  ['ssl_ocsp_status_ttl', 'ocsp-status-ttl', 31536000],
  ['ssl_crl_status_ttl', 'crl-status-ttl', 31536000],
  ['write_pcap_single_quota', 'logging-pcap-quota', 1048576],
  ['log_level', 'logging-level', 10], ['syslog_port', 'logging-syslog-port', 65535],
  ['syslog_facility', 'logging-syslog-facility', 23],
  ['syslog_level', 'logging-syslog-level', 10],
  ['cli.port', 'aux-cli-port', 65535],
  ['webhook.ping_interval', 'webhook-ping-interval', 2147483647],
  ['webhook.nbr_update_interval', 'webhook-neighbor-update-interval', 2147483647],
  ['webhook.nbr_tag_refresh_age', 'webhook-neighbor-tag-refresh-age', 2147483647],
] as const;

const systemTuningFields = [
  ['host_bufsz_min', 'host-buffer-min', 1500, 10000000],
  ['host_bufsz_max_multiplier', 'host-buffer-max-multiplier', 1, 1024000000],
  ['host_write_full', 'host-write-full', 1024, 1024000000],
  ['host_io_batch', 'host-io-batch', 16384, 16777216],
  ['tls_write_chunk', 'tls-write-chunk', 1024, 1048576],
  ['host_open_timeout', 'host-open-timeout', 0, 65535],
  ['host_idle_timeout', 'host-idle-timeout', 0, 65535],
  ['nbr_cache_size', 'neighbor-cache-size', 1, 2147483647],
] as const;

const debugFields = [
  ['log_data_crc', 'data-crc'], ['log_sockets', 'sockets'],
  ['log_online_cx_name', 'online-name'], ['log_srclines', 'source-lines'],
  ['log_srclines_always', 'source-lines-always'],
] as const;

const captureBooleanFields = [
  ['local.enabled', 'local-enabled'], ['remote.enabled', 'remote-enabled'],
  ['options.calculate_checksums', 'checksums'],
] as const;

const initialRuntimeMetrics: RuntimeMetricsSnapshot = {
  state: 'starting',
  detail: 'Waiting for the first runtime metrics sample.',
  checkedAtUnixMs: null,
  lastSuccessAtUnixMs: null,
  totals: {workers: 0, sessionsTotal: 0, sessionsActive: 0, bytesUp: 0, bytesDown: 0},
  listeners: [],
  history: [],
};

const initialSessionActivity: SessionActivitySnapshot = {
  state: 'starting',
  detail: 'Waiting for the first session activity sample.',
  checkedAtUnixMs: null,
  lastSuccessAtUnixMs: null,
  total: 0,
  speedUp: 0,
  speedDown: 0,
  protocols: [],
};

const initialTlsCache: TlsCacheSnapshot = {
  state: 'starting',
  detail: 'Waiting for the first TLS cache sample.',
  checkedAtUnixMs: null,
  lastSuccessAtUnixMs: null,
  size: 0,
  capacity: 0,
};

const initialNeighbors: NeighborSnapshot = {
  state: 'starting',
  detail: 'Waiting for the first neighborhood sample.',
  checkedAtUnixMs: null,
  lastSuccessAtUnixMs: null,
  hostsTotal: 0,
  activeToday: 0,
  activeWeek: 0,
  taggedHosts: 0,
  observations: 0,
  bytesUp: 0,
  bytesDown: 0,
};

const initialInterfaces: InterfaceSnapshot = {
  state: 'starting',
  detail: 'Waiting for the first interface synchronization sample.',
  checkedAtUnixMs: null,
  lastSuccessAtUnixMs: null,
  generation: 0,
  synchronizationRunning: false,
  synchronizationAttempts: 0,
  synchronizationSuccesses: 0,
  synchronizationErrors: 0,
  eventDatagrams: 0,
  changedEventDatagrams: 0,
  interfaces: 0,
  addresses: 0,
  ipv4Addresses: 0,
  ipv6Addresses: 0,
  lastErrorCode: null,
};

const initialEvents: EventSnapshot = {
  source: 'gui-core',
  smithproxyEventsAvailable: false,
  events: [],
};

const initialAlerts: AlertSnapshot = {
  source: 'gui-core',
  generatedAtUnixMs: 0,
  alerts: [],
};

const initialAudit: AuditSnapshot = {
  source: 'gui-core',
  actorAvailable: false,
  entries: [],
};

const initialJobs: JobSnapshot = {
  source: 'gui-core',
  generatedAtUnixMs: 0,
  ownerAvailable: false,
  jobs: [],
};

@customElement('smithproxy-gui')
export class SmithproxyApp extends LitElement {
  @property({reflect: true}) mode: 'standalone' | 'embedded' = 'standalone';
  @state() private snapshot: ConfigSnapshot | undefined;
  @state() private loadingError?: string;
  @state() private activeSection = 'Dashboard';
  @state() private drawers: ReadonlyArray<DrawerEntry> = [];
  @state() private draftObjects = new Set<string>();
  @state() private systemStatus: SystemStatus = connectingSystemStatus;
  @state() private apiVersion = 'discovering';
  @state() private capabilityBootstrapState: CapabilityBootstrapState = 'discovering';
  @state() private capabilityCheckedAtUnixMs: number | null = null;
  @state() private capabilityLastSuccessAtUnixMs: number | null = null;
  @state() private capabilityError: string | undefined;
  @state() private transactionCapabilityState: TransactionCapabilityState = 'unknown';
  @state() private gatewaySession: GatewaySession | undefined;
  @state() private gatewaySessionError: string | undefined;
  @state() private runtimeMetrics: RuntimeMetricsSnapshot = initialRuntimeMetrics;
  @state() private sessionActivity: SessionActivitySnapshot = initialSessionActivity;
  @state() private tlsCache: TlsCacheSnapshot = initialTlsCache;
  @state() private neighbors: NeighborSnapshot = initialNeighbors;
  @state() private interfaces: InterfaceSnapshot = initialInterfaces;
  @state() private operationalEvents: EventSnapshot = initialEvents;
  @state() private operationalAlerts: AlertSnapshot = initialAlerts;
  @state() private managementAudit: AuditSnapshot = initialAudit;
  @state() private backendJobs: JobSnapshot = initialJobs;
  @state() private eventStreamState: EventStreamState = 'connecting';
  @state() private eventStreamError: string | undefined;
  @state() private eventStreamConnectedAtUnixMs: number | null = null;
  @state() private eventStreamLastMessageAtUnixMs: number | null = null;
  @state() private eventStreamLastDisconnectAtUnixMs: number | null = null;
  @state() private eventStreamReconnectCount = 0;
  @state() private eventCategoryFilter: EventCategoryFilter = 'all';
  @state() private eventsError: string | undefined;
  @state() private alertsError: string | undefined;
  @state() private auditError: string | undefined;
  @state() private jobsError: string | undefined;
  @state() private focusMode = false;
  @state() private configReadAvailable = false;
  @state() private configWriteAvailable = false;
  @state() private structuralDraftsAvailable = false;
  @state() private draftAvailable = false;
  @state() private draftPreflightAvailable = false;
  @state() private jobsAvailable = false;
  @state() private draftVersion = 0;
  @state() private draftChangeCount = 0;
  @state() private workspaceDraft: DraftSnapshot | undefined;
  @state() private discardDraftArmed = false;
  @state() private draftSaving = false;
  @state() private draftError: string | undefined;
  @state() private draftPreflight: DraftPreflight | undefined;
  @state() private draftPreflightError: string | undefined;
  @state() private draftValidation: DraftValidation | undefined;
  @state() private draftValidationError: string | undefined;
  @state() private draftValidating = false;
  @state() private draftCommitting = false;
  @state() private draftCommitArmed = false;
  @state() private draftCommitError: string | undefined;
  @state() private draftCommitResult: DraftCommit | undefined;
  @state() private draftRemovalArmedKey: string | undefined;
  @state() private structuralDeleteArmedKey: string | undefined;
  @state() private drawerError: string | undefined;
  @state() private dirtyDrawerKeys = new Set<string>();
  @state() private pendingCloseIndex: number | undefined;
  @state() private configError: string | undefined;
  @state() private configRefreshDeferred = false;
  @state() private searchQuery = '';

  private readonly previewClient = new FakeConfigClient();
  private readonly drawerStore = new DrawerStore();
  private runtime?: RuntimeConfig;
  private systemClient?: SystemClient;
  private configClient?: ApiConfigClient;
  private draftClient?: DraftClient;
  private systemProbeTimer: number | undefined;
  private systemProbeInFlight = false;
  private systemProbePending = false;
  private capabilityRefresh: Promise<void> | undefined;
  private nextCapabilityRefreshAt = 0;
  private monitoringAccessEpoch = 0;
  private configurationAccessEpoch = 0;
  private eventStreamEpoch = 0;
  private closeEventStream: (() => void) | undefined;
  private eventStreamDegradedTimer: number | undefined;
  private configRefreshInFlight = false;
  private nextConfigRefreshAt = 0;
  private drawerHistoryDepth = 0;
  private drawerHistoryNavigationPending = false;
  private drawerOrigins: HTMLElement[] = [];
  private readonly drawerInitialChanges = new Map<string, ReadonlyMap<string, DraftScalar>>();
  private readonly referencePreviewValues = new Map<string, string>();
  private pendingReturnFocus: HTMLElement | undefined;
  private searchReturnSection = 'Dashboard';
  private managementApiAvailable = false;
  private metricsAvailable = false;
  private sessionActivityAvailable = false;
  private tlsMonitoringAvailable = false;
  private neighborMonitoringAvailable = false;
  private interfaceMonitoringAvailable = false;
  private eventsAvailable = false;
  private alertsAvailable = false;
  private auditAvailable = false;

  static styles = css`
    :host {
      --app-canvas: var(--st-canvas, #0c1923);
      --app-surface: var(--st-surface, #122b36);
      --app-raised: var(--st-surface-raised, #173440);
      --app-text: var(--st-text, #e8eff1);
      --app-muted: var(--st-muted, #a6bac3);
      --app-border: var(--st-border, #2c4855);
      --app-border-strong: var(--st-border-strong, #6b818c);
      --app-brand: var(--st-brand, #d99152);
      --app-on-brand: var(--st-on-brand, #20160e);
      --app-input: var(--st-input, #0c1923);
      --app-focus: var(--st-focus, #a2c3ca);
      --app-success: var(--st-success, #58d68d);
      --app-success-bg: var(--st-success-bg, #142c20);
      --app-warning: var(--st-warning, #f5b942);
      --app-warning-bg: var(--st-warning-bg, #342b1d);
      --app-danger: var(--st-danger, #ff7892);
      display: block;
      min-width: 0;
      color: var(--app-text);
      background: var(--app-canvas);
      font: 14px/1.45 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    :host([mode='standalone']) {
      min-height: 100dvh;
    }

    * { box-sizing: border-box; }
    button, input, select, textarea { font: inherit; }
    button, a, input, select, textarea { outline-color: var(--app-focus); }
    button { color: inherit; }

    .shell {
      display: grid;
      grid-template: minmax(0, 1fr) 30px / 216px minmax(0, 1fr);
      min-height: inherit;
      height: 100dvh;
      overflow: hidden;
      background: var(--app-canvas);
    }

    :host([mode='embedded']) .shell { height: min(860px, 100dvh); }

    .sidebar {
      grid-row: 1;
      padding: 18px 12px;
      border-right: 1px solid var(--app-border);
      background: var(--app-surface);
    }

    .brand { display: flex; gap: 10px; align-items: center; margin: 0 8px 24px; font-weight: 700; }
    .brand-mark { display: grid; width: 30px; height: 30px; place-items: center; border-radius: 4px; background: var(--app-brand); color: var(--app-on-brand); }
    nav { display: grid; gap: 4px; }
    nav button { width: 100%; padding: 10px 12px; border: 0; border-radius: 3px; background: transparent; color: var(--app-muted); text-align: left; cursor: pointer; }
    nav button:hover { background: var(--app-raised); color: var(--app-text); }
    nav button[aria-current='page'] { background: var(--app-raised); color: var(--app-text); box-shadow: inset 3px 0 var(--app-brand); }

    .main { display: grid; grid-template-rows: 58px minmax(0, 1fr); min-width: 0; min-height: 0; }
    .topbar { display: flex; gap: 16px; align-items: center; padding: 0 20px; border-bottom: 1px solid var(--app-border); background: color-mix(in srgb, var(--app-surface) 88%, transparent); }
    .topbar h1 { margin: 0; font-size: 18px; }
    .topbar p { flex: 1; margin: 0; color: var(--app-muted); }
    .search { width: min(300px, 32vw); padding: 8px 10px; border: 1px solid var(--app-border); border-radius: 3px; background: var(--app-input); color: var(--app-text); }

    .workspace { position: relative; min-width: 0; min-height: 0; overflow: hidden; }
    .content-layer { height: 100%; }
    .content { height: 100%; overflow: auto; padding: 22px; }
    .content:focus-visible { outline: 2px solid var(--app-focus); outline-offset: -2px; }
    .section-head { display: flex; flex-wrap: wrap; gap: 16px; align-items: end; justify-content: space-between; margin-bottom: 16px; }
    .section-head h2 { margin: 0 0 3px; font-size: 20px; }
    .section-head p { margin: 0; color: var(--app-muted); }
    .structural-action { display: grid; max-width: 260px; gap: 4px; justify-items: end; text-align: right; }
    .object-structural-action { max-width: 520px; }
    .structural-buttons { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; }
    .structural-action small { color: var(--app-muted); }
    .primary { padding: 8px 13px; border: 1px solid var(--app-brand); border-radius: 3px; background: var(--app-brand); color: var(--app-on-brand); font-weight: 650; cursor: pointer; }
    button:disabled { cursor: not-allowed; opacity: .55; }

    .dashboard { display: grid; gap: 18px; }
    .metric-grid { display: grid; grid-template-columns: repeat(4, minmax(150px, 1fr)); gap: 12px; }
    .metric, .monitor-panel { border: 1px solid var(--app-border); border-radius: 4px; background: var(--app-surface); }
    .metric { min-height: 116px; padding: 15px 16px; }
    .metric-label { color: var(--app-muted); font-size: 12px; font-weight: 650; letter-spacing: .03em; text-transform: uppercase; }
    .metric-value { display: block; margin-top: 8px; font-size: 25px; font-weight: 700; }
    .metric-value.success { color: var(--app-success); }
    .metric-value.warning { color: var(--app-warning); }
    .metric-value.danger { color: var(--app-danger); }
    .metric-note { display: block; margin-top: 5px; color: var(--app-muted); font-size: 12px; }
    .monitor-panel { padding: 16px; }
    .monitor-panel h3 { margin: 0; font-size: 15px; }
    .monitor-panel p { margin: 4px 0 0; color: var(--app-muted); }
    .probe-history { display: grid; grid-template-columns: repeat(60, minmax(3px, 1fr)); gap: 3px; height: 52px; margin-top: 16px; align-items: end; }
    .probe { min-height: 12px; height: 100%; border-radius: 1px; background: var(--app-border); }
    .probe.ready { background: var(--app-success); }
    .probe.starting, .probe.unreachable, .probe.unconfigured { background: var(--app-warning); }
    .probe.unauthorized, .probe.error { background: var(--app-danger); }
    .trend-grid { display: grid; grid-template-columns: repeat(2, minmax(260px, 1fr)); gap: 14px; margin-top: 16px; }
    .trend-chart { min-width: 0; padding: 13px; border: 1px solid var(--app-border); background: var(--app-canvas); }
    .trend-chart header { display: flex; justify-content: space-between; gap: 12px; align-items: baseline; }
    .trend-chart header strong { font-size: 13px; }
    .trend-chart header span { color: var(--app-muted); font-size: 12px; }
    .trend-bars { display: grid; grid-template-columns: repeat(60, minmax(2px, 1fr)); align-items: end; gap: 2px; height: 100px; margin-top: 12px; }
    .trend-bar { height: max(2px, var(--bar-height)); background: var(--app-brand); opacity: .88; }
    .trend-bar.traffic { background: var(--app-success); }
    .trend-bar.unavailable { height: 100%; background: repeating-linear-gradient(135deg, var(--app-danger) 0 2px, transparent 2px 5px); opacity: .65; }
    .trend-bar.empty { height: 2px; background: var(--app-border); opacity: .55; }
    .scope-note { padding: 12px 14px; border-left: 3px solid var(--app-brand); background: var(--app-raised); color: var(--app-muted); }
    .runtime-summary { display: grid; gap: 12px; }
    .runtime-heading { display: flex; gap: 16px; align-items: end; justify-content: space-between; }
    .runtime-heading h3 { margin: 0; font-size: 16px; }
    .runtime-heading p { margin: 3px 0 0; color: var(--app-muted); }
    .runtime-state { color: var(--app-muted); font-size: 12px; }
    .runtime-state.success { color: var(--app-success); }
    .runtime-state.warning { color: var(--app-warning); }
    .runtime-state.danger { color: var(--app-danger); }
    .listener-table { width: 100%; border-collapse: collapse; }
    .listener-table th, .listener-table td { padding: 11px 13px; border-bottom: 1px solid var(--app-border); text-align: right; }
    .listener-table th:first-child, .listener-table td:first-child { text-align: left; }
    .listener-table th { color: var(--app-muted); font-size: 12px; font-weight: 600; }
    .listener-table tbody tr:last-child td { border-bottom: 0; }
    .listener-name { font-weight: 650; }
    .collector-table { overflow-x: auto; margin-top: 14px; }
    .metrics-message { padding: 11px 13px; border: 1px solid var(--app-border); border-radius: 3px; color: var(--app-muted); }
    .privacy-note { padding: 10px 13px; border-left: 3px solid var(--app-success); background: var(--app-success-bg); color: var(--app-muted); }
    .origin-note { padding: 9px 11px; border-left: 3px solid var(--app-warning); background: var(--app-warning-bg); color: var(--app-muted); font-size: 12px; }
    .origin-note strong { color: var(--app-text); }
    .origin-card { margin-top: 10px; padding: 12px; border: 1px solid color-mix(in srgb, var(--app-warning) 45%, var(--app-border)); border-radius: 2px; background: var(--app-warning-bg); }
    .origin-head { display: flex; gap: 12px; align-items: center; justify-content: space-between; }
    .origin-head code { overflow-wrap: anywhere; color: var(--app-text); font-weight: 700; }
    .origin-owner { color: var(--app-muted); font-size: 12px; }
    .origin-owner.locked, .origin-active { color: var(--app-warning); font-weight: 700; }
    .origin-chain { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1px; margin: 12px 0 0; padding: 0; list-style: none; background: var(--app-border); }
    .origin-step { display: grid; min-width: 0; gap: 4px; padding: 10px; background: var(--app-surface); }
    .origin-step.effective { background: color-mix(in srgb, var(--app-success-bg) 70%, var(--app-surface)); }
    .origin-step.pending { border: 1px dashed var(--app-brand); }
    .origin-kind { color: var(--app-muted); font-size: 10px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase; }
    .origin-value, .origin-id { overflow-wrap: anywhere; color: var(--app-text); }
    .origin-id { font-size: 12px; }
    .event-list { display: grid; overflow: hidden; border: 1px solid var(--app-border); border-radius: 4px; background: var(--app-surface); }
    .event-row { display: grid; grid-template-columns: 150px 78px minmax(180px, 1fr) 100px; gap: 14px; align-items: center; padding: 12px 14px; border-bottom: 1px solid var(--app-border); }
    .event-row:last-child { border-bottom: 0; }
    .event-time, .event-source { color: var(--app-muted); font-size: 12px; }
    .event-severity { font-size: 12px; font-weight: 700; letter-spacing: .03em; text-transform: uppercase; }
    .event-severity.info { color: var(--app-success); }
    .event-severity.notice, .event-severity.warning { color: var(--app-warning); }
    .event-severity.error, .event-severity.critical { color: var(--app-danger); }
    .event-filters { display: flex; flex-wrap: wrap; gap: 8px; margin: 14px 0; }
    .event-filters button[aria-pressed='true'] { border-color: var(--app-brand); color: var(--app-text); }
    .audit-row { display: grid; grid-template-columns: 150px 82px minmax(180px, 1fr) minmax(130px, .7fr); gap: 14px; align-items: center; padding: 12px 14px; border-bottom: 1px solid var(--app-border); }
    .audit-row:last-child { border-bottom: 0; }
    .audit-operation { min-width: 0; }
    .audit-operation small { display: block; overflow: hidden; color: var(--app-muted); text-overflow: ellipsis; white-space: nowrap; }
    .audit-request { overflow: hidden; color: var(--app-muted); font: 12px ui-monospace, SFMono-Regular, Consolas, monospace; text-overflow: ellipsis; white-space: nowrap; }
    .alert-list { display: grid; margin-top: 14px; border: 1px solid var(--app-border); background: var(--app-surface); }
    .alert-row { display: grid; grid-template-columns: 76px minmax(0, 1fr); gap: 14px; padding: 12px 14px; border-left: 3px solid var(--app-warning); border-bottom: 1px solid var(--app-border); }
    .alert-row:last-child { border-bottom: 0; }
    .alert-row.critical { border-left-color: var(--app-danger); }
    .alert-row p { margin: 3px 0 0; color: var(--app-muted); }
    .incident-list { display: grid; margin-top: 14px; border: 1px solid var(--app-border); background: var(--app-surface); }
    .incident-row { display: grid; grid-template-columns: 150px minmax(150px, 1fr) 110px 100px; gap: 14px; align-items: center; padding: 12px 14px; border-left: 3px solid var(--app-muted); border-bottom: 1px solid var(--app-border); }
    .incident-row:last-child { border-bottom: 0; }
    .incident-row.active { border-left-color: var(--app-danger); background: color-mix(in srgb, var(--app-danger) 10%, var(--app-surface)); }
    .incident-state { min-width: 0; }
    .incident-state strong, .incident-state small { display: block; }
    .incident-state small, .incident-time, .incident-duration { color: var(--app-muted); font-size: 12px; }
    .incident-state small { overflow: hidden; margin-top: 3px; text-overflow: ellipsis; white-space: nowrap; }
    .incident-duration { text-align: right; }
    .capacity-track { height: 8px; overflow: hidden; border-radius: 2px; background: var(--app-border); }
    .capacity-fill { height: 100%; border-radius: inherit; background: var(--app-brand); }

    .card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 12px; }
    .domain-card { padding: 16px; border: 1px solid var(--app-border); border-radius: 4px; background: var(--app-surface); }
    .domain-card header { display: flex; gap: 12px; align-items: start; justify-content: space-between; }
    .domain-card h3 { margin: 0; font-size: 16px; }
    .domain-card p { margin: 5px 0 0; color: var(--app-muted); }
    .domain-card dl { display: grid; grid-template-columns: 1fr auto; gap: 8px 16px; margin: 18px 0 0; }
    .domain-card dt { color: var(--app-muted); }
    .domain-card dd { margin: 0; font-variant-numeric: tabular-nums; text-align: right; }
    .object-row { grid-template-columns: minmax(150px, 1.2fr) 110px minmax(180px, 1fr) 90px; }
    .object-value { overflow: hidden; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; text-overflow: ellipsis; white-space: nowrap; }
    .object-section + .object-section { margin-top: 24px; }
    .object-section h3 { margin: 0 0 9px; font-size: 15px; }
    .system-grid { display: grid; grid-template-columns: repeat(2, minmax(260px, 1fr)); gap: 12px; }
    .system-grid .domain-card dl { grid-template-columns: minmax(110px, .6fr) minmax(150px, 1fr); }
    .system-grid .domain-card dd { overflow-wrap: anywhere; }
    .system-grid .job-card { grid-column: 1 / -1; }
    .job-list { display: grid; gap: 8px; margin-top: 16px; }
    .job-row { display: grid; grid-template-columns: minmax(145px, .8fr) minmax(170px, 1fr) minmax(120px, .7fr) 64px; gap: 14px; align-items: center; padding: 10px 12px; border: 1px solid var(--app-border); background: var(--app-canvas); }
    .job-row small { overflow: hidden; color: var(--app-muted); text-overflow: ellipsis; white-space: nowrap; }
    .job-progress { display: grid; grid-template-columns: minmax(80px, 1fr) 38px; gap: 8px; align-items: center; }
    .job-progress progress { width: 100%; accent-color: var(--app-brand); }

    .table { overflow: hidden; border: 1px solid var(--app-border); border-radius: 4px; background: var(--app-surface); }
    .row { display: grid; grid-template-columns: minmax(130px, 1.2fr) minmax(130px, 1fr) minmax(110px, 1fr) 90px 80px; gap: 16px; align-items: center; width: 100%; padding: 12px 14px; border: 0; border-bottom: 1px solid var(--app-border); background: transparent; text-align: left; cursor: pointer; }
    .row:last-child { border-bottom: 0; }
    .row:not(.heading):hover { background: var(--app-raised); }
    .row.heading { color: var(--app-muted); font-size: 12px; cursor: default; }
    .row strong { font-weight: 650; }
    .draft-row { display: grid; grid-template-columns: minmax(220px, .8fr) minmax(260px, 1.2fr) auto; gap: 18px; align-items: center; padding: 12px 14px; border-bottom: 1px solid var(--app-border); }
    .draft-row:last-child { border-bottom: 0; }
    .draft-row.heading { color: var(--app-muted); font-size: 12px; }
    .draft-path { overflow-wrap: anywhere; color: var(--app-muted); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; }
    .draft-actions { display: flex; flex-wrap: wrap; gap: 7px; justify-content: end; }
    .draft-value { overflow-wrap: anywhere; }
    .preflight { padding: 15px; border: 1px solid var(--app-border); border-radius: 3px; background: var(--app-surface); }
    .preflight h3 { margin: 0; font-size: 15px; }
    .preflight-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .preflight-actions { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; }
    .preflight-grid { display: grid; grid-template-columns: repeat(3, minmax(150px, 1fr)); gap: 10px; margin-top: 12px; }
    .preflight-check { padding: 10px 11px; border: 1px solid var(--app-border); background: var(--app-canvas); }
    .preflight-check small { display: block; color: var(--app-muted); }
    .preflight-check strong { display: block; margin-top: 3px; }
    .preflight-sections { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 12px; }
    .preflight-section { padding: 4px 7px; border: 1px solid var(--app-border); color: var(--app-muted); font-size: 12px; }
    .preflight-blockers { margin: 12px 0 0; padding-left: 20px; color: var(--app-warning); }
    .danger-button { border-color: var(--app-danger); background: transparent; color: var(--app-danger); }
    .status { display: inline-flex; width: fit-content; gap: 6px; align-items: center; color: var(--app-success); }
    .status::before { width: 7px; height: 7px; border-radius: 50%; background: currentColor; content: ''; }
    .status.disabled { color: var(--app-muted); }
    .row-meta { display: flex; min-width: 0; flex-wrap: wrap; gap: 5px; align-items: center; }
    .overlay-badge { padding: 1px 5px; border: 1px solid color-mix(in srgb, var(--app-warning) 55%, var(--app-border)); border-radius: 2px; background: var(--app-warning-bg); color: var(--app-warning); font-size: 10px; font-weight: 700; white-space: nowrap; }
    .pending-badge { padding: 1px 5px; border: 1px solid color-mix(in srgb, var(--app-brand) 60%, var(--app-border)); border-radius: 2px; color: var(--app-brand); font-size: 10px; font-weight: 700; white-space: nowrap; }
    .action { text-transform: capitalize; }

    .drawer {
      position: absolute;
      z-index: 10;
      inset: 0 0 0 20%;
      display: grid;
      grid-template-rows: auto minmax(0, 1fr) auto;
      min-width: min(620px, 100%);
      border-left: 1px solid var(--app-border-strong);
      background: var(--app-surface);
      box-shadow: -18px 0 44px var(--st-shadow, #0008);
      animation: slide-in 150ms ease-out;
    }
    .drawer[data-depth='1'] { z-index: 11; left: calc(20% + 52px); }
    .drawer[data-depth='2'] { z-index: 12; left: calc(20% + 104px); }
    .drawer[data-depth='3'] { z-index: 13; left: calc(20% + 156px); }
    .drawer[data-depth='4'] { z-index: 14; left: calc(20% + 208px); }
    .drawer[data-depth='5'] { z-index: 15; left: calc(20% + 260px); }
    .drawer.drawer.focus-mode { left: 0; min-width: 0; }
    .drawer-head { display: flex; gap: 12px; align-items: center; padding: 15px 18px; border-bottom: 1px solid var(--app-border); background: var(--app-raised); }
    .drawer-title { flex: 1; min-width: 0; }
    .drawer-title small { display: block; color: var(--app-muted); }
    .drawer-title h2 { overflow: hidden; margin: 1px 0 0; font-size: 18px; text-overflow: ellipsis; white-space: nowrap; }
    .icon-button { display: grid; width: 34px; height: 34px; place-items: center; border: 1px solid var(--app-border); border-radius: 3px; background: transparent; cursor: pointer; }
    .drawer-body { overflow: auto; padding: 22px 24px 32px; }
    .drawer-foot { display: flex; gap: 10px; align-items: center; padding: 12px 18px; border-top: 1px solid var(--app-border); background: var(--app-raised); }
    .drawer-foot .validation { flex: 1; color: var(--app-success); }
    .drawer-foot .validation.warning { color: var(--app-warning); }
    .secondary { padding: 8px 13px; border: 1px solid var(--app-border-strong); border-radius: 3px; background: transparent; cursor: pointer; }
    .form-grid { display: grid; grid-template-columns: minmax(120px, 0.35fr) minmax(240px, 1fr); gap: 18px 24px; max-width: 920px; }
    .form-grid.wide-form-grid { grid-template-columns: minmax(120px, .3fr) minmax(170px, 1fr) minmax(120px, .3fr) minmax(170px, 1fr); max-width: none; }
    .form-span { grid-column: 1 / -1; margin: var(--sp-space-3, 1rem) 0 0; }
    .form-grid label { align-self: center; color: var(--app-muted); }
    .form-grid input, .form-grid select, .form-grid textarea { width: 100%; padding: 9px 10px; border: 1px solid var(--app-border); border-radius: 3px; background: var(--app-input); color: var(--app-text); }
    .write-only-control { display: grid; grid-template-columns: minmax(150px, .35fr) minmax(180px, 1fr); gap: 8px; }
    .form-grid input[readonly], .form-grid select:disabled { border-style: dashed; opacity: .8; }
    .reference-stack { display: grid; gap: 7px; }
    .reference-edit { display: grid; grid-template-columns: minmax(160px, 1fr) auto; gap: 7px; align-items: center; }
    .reference-edit .reference { width: auto; }
    .reference { display: flex; align-items: center; justify-content: space-between; width: 100%; padding: 10px 12px; border: 1px solid var(--app-border); border-radius: 3px; background: var(--app-input); cursor: pointer; }
    .reference-advisory { display: flex; min-width: 0; gap: 10px; align-items: center; justify-content: space-between; padding: 8px 10px; border-left: 2px solid var(--app-warning); background: var(--app-warning-bg); color: var(--app-warning); }
    .reference-advisory strong { overflow-wrap: anywhere; color: var(--app-text); }
    .reference-advisory small { flex: 0 0 auto; color: inherit; }
    .section { margin-top: 28px; padding-top: 20px; border-top: 1px solid var(--app-border); }
    .section h3 { margin: 0 0 12px; font-size: 15px; }
    .impact { padding: 12px 14px; border: 1px solid color-mix(in srgb, var(--app-warning) 48%, var(--app-border)); border-radius: 3px; background: var(--app-warning-bg); color: var(--app-warning); }
    .usage { margin: 12px 0 0; padding: 0; list-style: none; }
    .usage li { border-bottom: 1px solid var(--app-border); }
    .usage li:last-child { border-bottom: 0; }
    .usage-static, .usage-link { display: flex; width: 100%; gap: 12px; align-items: center; justify-content: space-between; padding: 9px 0; }
    .usage-link { border: 0; background: transparent; color: var(--app-text); text-align: left; cursor: pointer; }
    .usage-link:hover { color: var(--app-brand); }
    .usage-kind { color: var(--app-muted); font-size: 12px; }

    .statusbar { grid-column: 1 / -1; display: flex; gap: 14px; align-items: center; overflow: hidden; padding: 0 12px; border-top: 1px solid var(--app-border); background: var(--app-raised); color: var(--app-muted); font-size: 12px; white-space: nowrap; }
    .system-state { color: var(--app-muted); }
    .system-state.success { color: var(--app-success); }
    .system-state.warning { color: var(--app-warning); }
    .system-state.danger { color: var(--app-danger); }
    .draft { color: var(--app-warning); }
    .status-action { overflow: hidden; padding: 0; border: 0; background: transparent; color: inherit; font: inherit; text-overflow: ellipsis; white-space: nowrap; cursor: pointer; }
    .status-action:hover { color: var(--app-text); }
    .status-action:focus-visible { outline: 2px solid var(--app-focus); outline-offset: 3px; }
    .spacer { flex: 1; }

    .error { margin: 24px; padding: 16px; border: 1px solid var(--app-danger); border-radius: 3px; color: var(--app-danger); }
    .empty-state { display: grid; height: 100%; place-content: center; padding: 24px; color: var(--app-muted); text-align: center; }
    .empty-state h2 { margin: 0 0 6px; color: var(--app-text); }
    .empty-state p { max-width: 460px; margin: 0; }

    @keyframes slide-in { from { translate: 32px 0; } }

    @media (max-width: 900px) {
      .shell { grid-template-columns: 76px minmax(0, 1fr); }
      .brand span:last-child, .nav-label { display: none; }
      .brand { justify-content: center; margin-inline: 0; }
      nav button { text-align: center; }
      .drawer { left: 8%; min-width: 0; }
      .drawer[data-depth='1'] { left: calc(8% + 18px); }
      .drawer[data-depth='2'] { left: calc(8% + 36px); }
      .drawer[data-depth='3'] { left: calc(8% + 54px); }
      .drawer[data-depth='4'] { left: calc(8% + 72px); }
      .drawer[data-depth='5'] { left: calc(8% + 90px); }
      .row { grid-template-columns: minmax(110px, 1fr) minmax(110px, 1fr) 80px; }
      .row > :nth-child(3), .row > :nth-child(5) { display: none; }
      .metric-grid { grid-template-columns: repeat(2, minmax(150px, 1fr)); }
      .trend-grid { grid-template-columns: 1fr; }
      .system-grid { grid-template-columns: 1fr; }
      .form-grid.wide-form-grid { grid-template-columns: minmax(120px, .35fr) minmax(220px, 1fr); max-width: 920px; }
      .status-tertiary { display: none; }
    }

    @media (max-width: 620px) {
      .shell { grid-template: 52px minmax(0, 1fr) 30px / minmax(0, 1fr); }
      .sidebar { grid-row: 1; display: flex; align-items: center; overflow-x: auto; padding: 6px 8px; border-right: 0; border-bottom: 1px solid var(--app-border); }
      .brand { margin: 0 10px 0 0; }
      nav { display: flex; }
      nav button { width: 42px; padding: 8px; }
      .main { grid-row: 2; grid-template-rows: 94px minmax(0, 1fr); }
      .topbar { display: grid; grid-template: auto auto / minmax(0, 1fr) auto; gap: 5px 8px; padding: 8px 12px; }
      .section-head { align-items: start; }
      .structural-action { max-width: 190px; }
      .topbar h1 { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .topbar p { display: none; }
      .topbar .search { display: block; grid-column: 1 / -1; width: 100%; max-width: none; }
      .content { padding: 14px; }
      .drawer { inset: 0; }
      .workspace .drawer[data-depth] { inset: 0; left: 0; }
      .form-grid { grid-template-columns: 1fr; gap: 7px; }
      .form-grid.wide-form-grid { grid-template-columns: 1fr; }
      .write-only-control { grid-template-columns: 1fr; }
      .form-grid > *, .reference-edit { min-width: 0; }
      .form-grid label:not(:first-child) { margin-top: 10px; }
      .statusbar { grid-row: 3; }
      .status-secondary { display: none; }
      .metric-grid { grid-template-columns: 1fr; }
      .object-row { grid-template-columns: minmax(120px, 1fr) 90px; }
      .object-row > :nth-child(3), .object-row > :nth-child(4) { display: none; }
      .event-row { grid-template-columns: 110px 66px minmax(120px, 1fr); }
      .incident-row { grid-template-columns: minmax(100px, .7fr) minmax(140px, 1fr); }
      .incident-duration, .incident-time { display: none; }
      .audit-row { grid-template-columns: 72px minmax(0, 1fr); }
      .audit-row .event-time, .audit-request { display: none; }
      .job-row { grid-template-columns: 1fr; gap: 7px; }
      .draft-row { grid-template-columns: 1fr; gap: 5px; }
      .preflight-grid { grid-template-columns: 1fr; }
      .preflight-heading { align-items: stretch; flex-direction: column; }
      .preflight-actions { justify-content: stretch; }
      .preflight-actions button { flex: 1; }
      .event-source { display: none; }
      .probe-history { gap: 2px; }
    }

    @media (prefers-reduced-motion: reduce) {
      .drawer { animation: none; }
    }
  `;

  connectedCallback(): void {
    super.connectedCallback();
    this.runtime = readRuntimeConfig(this);
    this.mode = this.runtime.mode;
    try {
      this.systemClient = new SystemClient(this.runtime.apiBase, this.runtime.basePath);
      this.configClient = new ApiConfigClient(this.runtime.apiBase);
      this.draftClient = new DraftClient(this.runtime.apiBase);
      void this.refreshConnection();
    } catch (error) {
      this.systemStatus = statusFromFailure(error);
    }
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
    window.addEventListener('online', this.handleOnline);
    window.addEventListener('beforeunload', this.handleBeforeUnload);
    window.addEventListener('popstate', this.handlePopState);
    void this.loadConfiguration();
  }

  disconnectedCallback(): void {
    this.clearSystemProbe();
    this.disconnectEventStream();
    this.systemClient?.cancelPendingRequests();
    this.configClient?.cancelPendingRequests();
    this.draftClient?.cancelPendingRequests();
    document.removeEventListener('visibilitychange', this.handleVisibilityChange);
    window.removeEventListener('online', this.handleOnline);
    window.removeEventListener('beforeunload', this.handleBeforeUnload);
    window.removeEventListener('popstate', this.handlePopState);
    super.disconnectedCallback();
  }

  private readonly handleVisibilityChange = (): void => {
    if (document.visibilityState === 'hidden') {
      this.clearSystemProbe();
      this.disconnectEventStream();
      this.eventStreamState = this.eventsAvailable ? 'paused' : 'unavailable';
    } else {
      void this.refreshConnection();
    }
  };

  private readonly handleOnline = (): void => {
    void this.refreshConnection();
  };

  private async refreshConnection(): Promise<void> {
    this.nextCapabilityRefreshAt = 0;
    await this.loadCapabilities();
    this.connectEventStream();
    await this.probeSystem();
  }

  private disconnectEventStream(): void {
    this.eventStreamEpoch += 1;
    this.clearEventStreamDegradedTimer();
    this.closeEventStream?.();
    this.closeEventStream = undefined;
  }

  private clearEventStreamDegradedTimer(): void {
    if (this.eventStreamDegradedTimer !== undefined) window.clearTimeout(this.eventStreamDegradedTimer);
    this.eventStreamDegradedTimer = undefined;
  }

  private markEventStreamReconnecting(): void {
    if (this.eventStreamState === 'invalid') return;
    this.eventStreamLastDisconnectAtUnixMs = Date.now();
    this.eventStreamReconnectCount += 1;
    if (this.eventStreamState !== 'live') {
      this.eventStreamState = 'connecting';
      return;
    }
    this.clearEventStreamDegradedTimer();
    this.eventStreamDegradedTimer = window.setTimeout(() => {
      this.eventStreamDegradedTimer = undefined;
      if (this.eventStreamState === 'live') this.eventStreamState = 'connecting';
    }, 2_000);
  }

  private connectEventStream(): void {
    if (!this.eventsAvailable) {
      this.eventStreamState = 'unavailable';
      return;
    }
    if (this.eventStreamState === 'invalid') return;
    if (this.closeEventStream || !this.systemClient || document.visibilityState === 'hidden') return;
    this.eventStreamState = 'connecting';
    const streamEpoch = ++this.eventStreamEpoch;
    const streamIsCurrent = (): boolean =>
      streamEpoch === this.eventStreamEpoch && this.eventsAvailable;
    this.closeEventStream = this.systemClient.subscribeEvents({
      snapshot: snapshot => {
        if (!streamIsCurrent()) return;
        this.clearEventStreamDegradedTimer();
        this.operationalEvents = snapshot;
        this.eventsError = undefined;
        this.eventStreamError = undefined;
        this.eventStreamLastMessageAtUnixMs = Date.now();
        this.eventStreamState = 'live';
      },
      event: event => {
        if (!streamIsCurrent()) return;
        this.clearEventStreamDegradedTimer();
        const withoutDuplicate = this.operationalEvents.events.filter(item => item.id !== event.id);
        this.operationalEvents = {
          ...this.operationalEvents,
          events: [...withoutDuplicate, event].slice(-60),
        };
        this.eventsError = undefined;
        this.eventStreamError = undefined;
        this.eventStreamLastMessageAtUnixMs = Date.now();
        this.eventStreamState = 'live';
      },
      invalid: error => {
        if (!streamIsCurrent()) return;
        this.disconnectEventStream();
        this.eventStreamError = error.message;
        this.eventStreamLastDisconnectAtUnixMs = Date.now();
        this.eventStreamState = 'invalid';
      },
      connection: state => {
        if (!streamIsCurrent()) return;
        if (state === 'open') this.eventStreamConnectedAtUnixMs = Date.now();
        else this.markEventStreamReconnecting();
      },
    });
  }

  private retryEventStream(): void {
    if (!this.eventsAvailable) return;
    this.disconnectEventStream();
    this.eventStreamError = undefined;
    this.eventStreamState = 'connecting';
    this.connectEventStream();
  }

  private readonly handleBeforeUnload = (event: BeforeUnloadEvent): void => {
    if (this.dirtyDrawerKeys.size === 0) return;
    event.preventDefault();
    event.returnValue = '';
  };

  private readonly handlePopState = (): void => {
    if (this.drawerHistoryNavigationPending) {
      this.drawerHistoryNavigationPending = false;
      const target = this.pendingReturnFocus;
      this.pendingReturnFocus = undefined;
      if (target?.isConnected) void this.updateComplete.then(() => target.focus());
      return;
    }
    if (this.drawers.some(entry => this.dirtyDrawerKeys.has(this.drawerKey(entry)))) {
      const hostState = typeof history.state === 'object' && history.state !== null ? history.state : {};
      history.pushState({...hostState, smithproxyGuiDrawer: true}, '', this.drawerUrl());
      this.requestCloseDrawer(this.drawers.length - 1);
      return;
    }
    this.drawerHistoryDepth = 0;
    this.restoreDrawerRoute();
    const target = this.pendingReturnFocus;
    this.pendingReturnFocus = undefined;
    if (target?.isConnected) void this.updateComplete.then(() => target.focus());
  };

  private clearSystemProbe(): void {
    if (this.systemProbeTimer !== undefined) window.clearTimeout(this.systemProbeTimer);
    this.systemProbeTimer = undefined;
  }

  private scheduleSystemProbe(): void {
    this.clearSystemProbe();
    if (!this.isConnected || !this.systemClient || document.visibilityState === 'hidden') return;
    this.systemProbeTimer = window.setTimeout(() => void this.probeSystem(), 5000);
  }

  private async probeSystem(): Promise<void> {
    this.clearSystemProbe();
    if (!this.isConnected || !this.systemClient || document.visibilityState === 'hidden') return;
    if (this.systemProbeInFlight) {
      this.systemProbePending = true;
      return;
    }
    this.systemProbeInFlight = true;
    if (Date.now() >= this.nextCapabilityRefreshAt) await this.loadCapabilities();
    const accessEpoch = this.monitoringAccessEpoch;
    const accessIsCurrent = (): boolean =>
      accessEpoch === this.monitoringAccessEpoch && this.managementApiAvailable;
    try {
      if (!accessIsCurrent()) return;
      const systemClient = this.systemClient;
      const systemStatus = statusFromSnapshot(await systemClient.status());
      if (!accessIsCurrent()) return;
      this.systemStatus = systemStatus;
      const [metrics, sessions, tlsCache, neighbors, interfaces, events, alerts, audit, jobs] = await Promise.allSettled([
        this.metricsAvailable ? systemClient.metricsSummary() : Promise.resolve(this.runtimeMetrics),
        this.sessionActivityAvailable ? systemClient.sessionActivity() : Promise.resolve(this.sessionActivity),
        this.tlsMonitoringAvailable ? systemClient.tlsCacheSummary() : Promise.resolve(this.tlsCache),
        this.neighborMonitoringAvailable ? systemClient.neighborSummary() : Promise.resolve(this.neighbors),
        this.interfaceMonitoringAvailable ? systemClient.interfaceSummary() : Promise.resolve(this.interfaces),
        this.eventsAvailable ? systemClient.recentEvents() : Promise.resolve(this.operationalEvents),
        this.alertsAvailable ? systemClient.activeAlerts() : Promise.resolve(this.operationalAlerts),
        this.auditAvailable ? systemClient.recentAudit() : Promise.resolve(this.managementAudit),
        this.jobsAvailable ? systemClient.jobs() : Promise.resolve(initialJobs),
      ] as const);
      if (!accessIsCurrent()) return;
      if (metrics.status === 'fulfilled') {
        this.runtimeMetrics = metrics.value;
      } else {
        this.runtimeMetrics = {
          ...this.runtimeMetrics,
          state: 'unavailable',
          detail: metrics.reason instanceof Error ? metrics.reason.message : 'Runtime metrics are unavailable.',
        };
      }
      if (sessions.status === 'fulfilled') {
        this.sessionActivity = sessions.value;
      } else {
        this.sessionActivity = {
          ...this.sessionActivity,
          state: 'unavailable',
          detail: sessions.reason instanceof Error ? sessions.reason.message : 'Session activity is unavailable.',
        };
      }
      if (tlsCache.status === 'fulfilled') {
        this.tlsCache = tlsCache.value;
      } else {
        this.tlsCache = {
          ...this.tlsCache,
          state: 'unavailable',
          detail: tlsCache.reason instanceof Error ? tlsCache.reason.message : 'TLS cache metrics are unavailable.',
        };
      }
      if (neighbors.status === 'fulfilled') {
        this.neighbors = neighbors.value;
      } else {
        this.neighbors = {
          ...this.neighbors,
          state: 'unavailable',
          detail: neighbors.reason instanceof Error ? neighbors.reason.message : 'Neighborhood metrics are unavailable.',
        };
      }
      if (interfaces.status === 'fulfilled') {
        this.interfaces = interfaces.value;
      } else {
        this.interfaces = {
          ...this.interfaces,
          state: 'unavailable',
          detail: interfaces.reason instanceof Error
            ? interfaces.reason.message : 'Interface monitoring is unavailable.',
        };
      }
      if (events.status === 'fulfilled') {
        this.operationalEvents = events.value;
        this.eventsError = undefined;
      } else {
        this.eventsError = events.reason instanceof Error ? events.reason.message : 'Operational events are unavailable.';
      }
      if (this.alertsAvailable) {
        if (alerts.status === 'fulfilled') {
          this.operationalAlerts = alerts.value;
          this.alertsError = undefined;
        } else {
          this.alertsError = alerts.reason instanceof Error
            ? alerts.reason.message : 'Operational alerts are unavailable.';
        }
      }
      if (this.auditAvailable) {
        if (audit.status === 'fulfilled') {
          this.managementAudit = audit.value;
          this.auditError = undefined;
        } else {
          this.auditError = audit.reason instanceof Error
            ? audit.reason.message : 'Management audit is unavailable.';
        }
      }
      if (jobs.status === 'fulfilled') {
        this.backendJobs = jobs.value;
        this.jobsError = undefined;
      } else {
        this.jobsError = jobs.reason instanceof Error ? jobs.reason.message : 'Backend jobs are unavailable.';
      }
      await this.refreshConfiguration();
    } catch (error) {
      if (!accessIsCurrent()) return;
      this.systemStatus = statusFromFailure(error);
      this.runtimeMetrics = {
        ...this.runtimeMetrics,
        state: 'unavailable',
        detail: 'Runtime metrics are unavailable while the GUI core is offline.',
      };
      this.sessionActivity = {
        ...this.sessionActivity,
        state: 'unavailable',
        detail: 'Session activity is unavailable while the GUI core is offline.',
      };
      this.tlsCache = {
        ...this.tlsCache,
        state: 'unavailable',
        detail: 'TLS cache metrics are unavailable while the GUI core is offline.',
      };
      this.neighbors = {
        ...this.neighbors,
        state: 'unavailable',
        detail: 'Neighborhood metrics are unavailable while the GUI core is offline.',
      };
      this.interfaces = {
        ...this.interfaces,
        state: 'unavailable',
        detail: 'Interface monitoring is unavailable while the GUI core is offline.',
      };
      this.auditError = 'Management audit is unavailable while the GUI core is offline.';
      this.jobsError = 'Backend jobs are unavailable while the GUI core is offline.';
    } finally {
      this.systemProbeInFlight = false;
      if (this.systemProbePending) {
        this.systemProbePending = false;
        void this.probeSystem();
      } else {
        this.scheduleSystemProbe();
      }
    }
  }

  private updateMonitoringCapabilities(
    features: SystemCapabilities['features'] | undefined,
    smithproxyState?: SmithproxyState,
  ): void {
    this.systemClient?.cancelPendingRequests();
    this.monitoringAccessEpoch += 1;
    const eventsWereAvailable = this.eventsAvailable;
    this.metricsAvailable = features?.metrics ?? false;
    this.sessionActivityAvailable = features?.sessionActivity ?? false;
    this.tlsMonitoringAvailable = features?.tlsMonitoring ?? false;
    this.neighborMonitoringAvailable = features?.neighborMonitoring ?? false;
    this.interfaceMonitoringAvailable = features?.interfaceMonitoring ?? false;
    this.eventsAvailable = features?.events ?? false;
    this.alertsAvailable = features?.alerts ?? false;
    this.auditAvailable = features?.audit ?? false;
    this.jobsAvailable = features?.jobs ?? false;
    this.managementApiAvailable = this.metricsAvailable || this.sessionActivityAvailable ||
      this.tlsMonitoringAvailable || this.neighborMonitoringAvailable ||
      this.interfaceMonitoringAvailable || this.eventsAvailable || this.alertsAvailable ||
      this.auditAvailable || this.jobsAvailable;

    if (!this.metricsAvailable) {
      this.runtimeMetrics = {...initialRuntimeMetrics, state: 'unavailable',
        detail: 'Runtime metrics are not available for this management session.'};
    }
    if (!this.sessionActivityAvailable) {
      this.sessionActivity = {...initialSessionActivity, state: 'unavailable',
        detail: 'Session activity is not available for this management session.'};
    }
    if (!this.tlsMonitoringAvailable) {
      this.tlsCache = {...initialTlsCache, state: 'unavailable',
        detail: 'TLS cache monitoring is not available for this management session.'};
    }
    if (!this.neighborMonitoringAvailable) {
      this.neighbors = {...initialNeighbors, state: 'unavailable',
        detail: 'Neighborhood monitoring is not available for this management session.'};
    }
    if (!this.interfaceMonitoringAvailable) {
      this.interfaces = {...initialInterfaces, state: 'unavailable',
        detail: 'Interface monitoring is not available for this management session.'};
    }
    if (!this.eventsAvailable) {
      this.disconnectEventStream();
      this.operationalEvents = initialEvents;
      this.eventsError = undefined;
      this.eventStreamError = undefined;
      this.eventStreamState = 'unavailable';
      this.eventStreamConnectedAtUnixMs = null;
      this.eventStreamLastMessageAtUnixMs = null;
      this.eventStreamLastDisconnectAtUnixMs = null;
      this.eventStreamReconnectCount = 0;
    } else if (!eventsWereAvailable) {
      this.eventsError = undefined;
      this.eventStreamError = undefined;
      this.connectEventStream();
    }
    if (!this.alertsAvailable) {
      this.operationalAlerts = initialAlerts;
      this.alertsError = 'Operational alerts are not available for this management session.';
    }
    if (!this.auditAvailable) {
      this.managementAudit = initialAudit;
      this.auditError = 'Management audit is not available for this management session.';
    }
    if (!this.jobsAvailable) {
      this.backendJobs = initialJobs;
      this.jobsError = undefined;
    }
    if (!this.managementApiAvailable && smithproxyState) {
      this.systemStatus = {
        ...connectingSystemStatus,
        core: 'online',
        smithproxy: smithproxyState,
        detail: 'Management monitoring is not available for this gateway session.',
      };
    }
  }

  private clearEditorChain(): void {
    this.drawerStore.clear();
    this.drawerInitialChanges.clear();
    this.drawers = [];
    this.drawerOrigins = [];
    this.dirtyDrawerKeys = new Set<string>();
    this.pendingCloseIndex = undefined;
    this.pendingReturnFocus = undefined;
    this.drawerHistoryDepth = 0;
    this.drawerError = undefined;
    this.focusMode = false;
    this.replaceDrawerRoute();
  }

  private clearDraftSessionState(): void {
    this.workspaceDraft = undefined;
    this.draftVersion = 0;
    this.draftChangeCount = 0;
    this.draftObjects = new Set<string>();
    this.discardDraftArmed = false;
    this.invalidateDraftOperations();
    this.clearEditorChain();
  }

  private invalidateDraftOperations(): void {
    this.draftClient?.cancelPendingRequests();
    this.draftSaving = false;
    this.draftError = undefined;
    this.draftPreflight = undefined;
    this.draftPreflightError = undefined;
    this.draftValidation = undefined;
    this.draftValidationError = undefined;
    this.draftValidating = false;
    this.draftCommitting = false;
    this.draftCommitArmed = false;
    this.draftCommitError = undefined;
    this.draftCommitResult = undefined;
    this.draftRemovalArmedKey = undefined;
  }

  private clearPrivilegedConfigurationState(): void {
    this.configClient?.cancelPendingRequests();
    if (this.snapshot?.source === 'live') this.snapshot = undefined;
    this.clearDraftSessionState();
    this.configRefreshInFlight = false;
    this.configRefreshDeferred = false;
    this.configError = undefined;
    this.searchQuery = '';
    if (this.activeSection === 'Search') this.activeSection = 'Dashboard';
  }

  private configurationAccessIsCurrent(epoch: number): boolean {
    return epoch === this.configurationAccessEpoch && this.configReadAvailable;
  }

  private draftAccessIsCurrent(epoch: number): boolean {
    return this.configurationAccessIsCurrent(epoch) && this.draftAvailable;
  }

  private async loadCapabilities(): Promise<void> {
    if (!this.systemClient) return;
    if (this.capabilityRefresh) return this.capabilityRefresh;
    const refresh = this.refreshCapabilities();
    this.capabilityRefresh = refresh;
    try {
      await refresh;
    } finally {
      if (this.capabilityRefresh === refresh) this.capabilityRefresh = undefined;
    }
  }

  private async refreshCapabilities(): Promise<void> {
    this.capabilityBootstrapState = this.capabilityCheckedAtUnixMs === null ? 'discovering' : 'refreshing';
    this.nextCapabilityRefreshAt = Date.now() + 30_000;
    try {
      const systemClient = this.systemClient;
      if (!systemClient) throw new Error('System API client is unavailable.');
      const [capabilitiesResult, sessionResult] = await Promise.allSettled([
        systemClient.capabilities(),
        systemClient.authSession(),
      ] as const);
      if (sessionResult.status === 'fulfilled') {
        this.gatewaySession = sessionResult.value;
        this.gatewaySessionError = undefined;
      } else {
        this.gatewaySession = undefined;
        this.gatewaySessionError = sessionResult.status === 'rejected' &&
          sessionResult.reason instanceof Error
          ? sessionResult.reason.message
          : 'Gateway session diagnostics are unavailable.';
      }
      if (capabilitiesResult.status === 'rejected') throw capabilitiesResult.reason;
      const capabilities = capabilitiesResult.value;
      const privilegedConfiguration = capabilities.features.configRead ||
        capabilities.features.configWrite || capabilities.features.drafts ||
        capabilities.features.draftPreflight;
      if (privilegedConfiguration &&
          (sessionResult.status !== 'fulfilled' || sessionResult.value.mode !== 'gateway' ||
           !sessionResult.value.authenticated)) {
        throw new Error('Privileged capabilities require a verified trusted gateway session.');
      }
      const managementCapabilities = capabilities.features.jobs || capabilities.features.events ||
        capabilities.features.alerts || capabilities.features.audit || capabilities.features.metrics ||
        capabilities.features.sessionActivity || capabilities.features.tlsMonitoring ||
        capabilities.features.neighborMonitoring || capabilities.features.interfaceMonitoring;
      if (managementCapabilities && sessionResult.status === 'fulfilled' &&
          sessionResult.value.mode === 'gateway' && !sessionResult.value.authenticated) {
        throw new Error('Management capabilities require a verified trusted gateway session.');
      }
      const draftWasAvailable = this.draftAvailable;
      const configReadWasAvailable = this.configReadAvailable;
      const configWriteWasAvailable = this.configWriteAvailable;
      const structuralDraftsWereAvailable = this.structuralDraftsAvailable;
      const draftPreflightWasAvailable = this.draftPreflightAvailable;
      const nextConfigReadAvailable = capabilities.features.configRead;
      const nextConfigWriteAvailable = capabilities.features.configWrite;
      const nextStructuralDraftsAvailable = capabilities.features.structuralDrafts;
      const nextDraftAvailable = capabilities.features.drafts;
      const nextDraftPreflightAvailable = capabilities.features.draftPreflight;
      const configurationCapabilitiesChanged =
        nextConfigReadAvailable !== configReadWasAvailable ||
        nextConfigWriteAvailable !== configWriteWasAvailable ||
        nextStructuralDraftsAvailable !== structuralDraftsWereAvailable ||
        nextDraftAvailable !== draftWasAvailable ||
        nextDraftPreflightAvailable !== draftPreflightWasAvailable;
      this.apiVersion = capabilities.apiVersion;
      this.transactionCapabilityState = capabilities.transactionState;
      this.configReadAvailable = nextConfigReadAvailable;
      this.configWriteAvailable = nextConfigWriteAvailable;
      this.structuralDraftsAvailable = nextStructuralDraftsAvailable;
      this.draftAvailable = nextDraftAvailable;
      this.draftPreflightAvailable = nextDraftPreflightAvailable;
      if (configurationCapabilitiesChanged) this.configurationAccessEpoch += 1;
      if (configReadWasAvailable && !this.configReadAvailable) {
        this.clearPrivilegedConfigurationState();
      } else if (draftWasAvailable && !this.draftAvailable) {
        this.clearDraftSessionState();
      } else if (configurationCapabilitiesChanged) {
        this.invalidateDraftOperations();
      }
      if (!this.configReadAvailable) this.configRefreshDeferred = false;
      this.updateMonitoringCapabilities(capabilities.features, capabilities.smithproxyState);
      if (!this.draftPreflightAvailable) {
        this.draftPreflight = undefined;
        this.draftPreflightError = undefined;
      }
      if (capabilities.features.configRead && this.snapshot?.source !== 'live') {
        void this.refreshConfiguration(true);
      }
      if (this.draftAvailable && configurationCapabilitiesChanged) void this.loadDraft();
      const completedAt = Date.now();
      this.capabilityBootstrapState = 'ready';
      this.capabilityCheckedAtUnixMs = completedAt;
      this.capabilityLastSuccessAtUnixMs = completedAt;
      this.capabilityError = undefined;
    } catch (error) {
      const configurationWasAvailable = this.configReadAvailable || this.configWriteAvailable ||
        this.draftAvailable || this.draftPreflightAvailable;
      this.apiVersion = 'unavailable';
      this.transactionCapabilityState = 'unavailable';
      this.configReadAvailable = false;
      if (configurationWasAvailable) {
        this.configurationAccessEpoch += 1;
        this.clearPrivilegedConfigurationState();
      }
      this.configRefreshDeferred = false;
      this.configWriteAvailable = false;
      this.structuralDraftsAvailable = false;
      this.draftAvailable = false;
      this.draftPreflightAvailable = false;
      this.updateMonitoringCapabilities(undefined);
      const failure = statusFromFailure(error);
      this.systemStatus = failure;
      this.capabilityBootstrapState = 'unavailable';
      this.capabilityCheckedAtUnixMs = Date.now();
      this.capabilityError = failure.detail;
      this.draftPreflight = undefined;
      this.draftPreflightError = undefined;
    }
  }

  private async refreshConfiguration(force = false): Promise<void> {
    if (!this.configReadAvailable || !this.configClient || this.configRefreshInFlight) return;
    const now = Date.now();
    if (!force && now < this.nextConfigRefreshAt) return;
    if (this.draftChangeCount > 0 || this.drawers.length > 0 || this.draftSaving ||
        this.draftCommitting) {
      this.configRefreshDeferred = true;
      return;
    }

    this.configRefreshInFlight = true;
    const accessEpoch = this.configurationAccessEpoch;
    this.nextConfigRefreshAt = now + 30_000;
    try {
      const snapshot = await this.configClient.loadSnapshot();
      if (!this.configurationAccessIsCurrent(accessEpoch)) return;
      this.snapshot = snapshot;
      this.restoreDrawerRoute();
      this.configError = undefined;
      this.configRefreshDeferred = false;
    } catch (error) {
      if (!this.configurationAccessIsCurrent(accessEpoch)) return;
      this.configError = error instanceof Error ? error.message : 'Live configuration is unavailable.';
    } finally {
      if (accessEpoch === this.configurationAccessEpoch) this.configRefreshInFlight = false;
    }
  }

  private systemStatusTitle(): string {
    const checked = this.systemStatus.checkedAtUnixMs === null
      ? 'not checked yet'
      : new Date(this.systemStatus.checkedAtUnixMs).toLocaleString();
    return `${this.systemStatus.detail} Last Smithproxy check: ${checked}.`;
  }

  private enabledCapabilityCount(): number {
    return [
      this.configReadAvailable, this.configWriteAvailable, this.draftAvailable,
      this.draftPreflightAvailable, this.jobsAvailable, this.eventsAvailable,
      this.alertsAvailable, this.auditAvailable, this.metricsAvailable,
      this.sessionActivityAvailable, this.tlsMonitoringAvailable,
      this.neighborMonitoringAvailable, this.interfaceMonitoringAvailable,
    ].filter(Boolean).length;
  }

  private gatewayStatus(): {label: string; tone: 'success' | 'warning' | 'danger'; detail: string} {
    if (this.gatewaySessionError) {
      return {label: 'Unavailable', tone: 'danger', detail: this.gatewaySessionError};
    }
    if (!this.gatewaySession) {
      return {label: 'Discovering', tone: 'warning', detail: 'Checking trusted gateway handoff.'};
    }
    if (this.gatewaySession.mode === 'disabled') {
      return {
        label: 'Disabled',
        tone: 'warning',
        detail: 'The GUI core has no trusted gateway secret; configuration APIs remain fail-closed.',
      };
    }
    if (!this.gatewaySession.authenticated) {
      return {
        label: 'Rejected',
        tone: 'danger',
        detail: 'This request did not receive a valid trusted gateway handoff.',
      };
    }
    return {
      label: 'Verified',
      tone: 'success',
      detail: 'Saslik authenticated this request and the GUI core verified its gateway handoff.',
    };
  }

  private downloadDiagnostics(): void {
    let gatewayState: GatewayDiagnosticState = 'verified';
    if (this.gatewaySessionError) gatewayState = 'unavailable';
    else if (!this.gatewaySession) gatewayState = 'discovering';
    else if (this.gatewaySession.mode === 'disabled') gatewayState = 'disabled';
    else if (!this.gatewaySession.authenticated) gatewayState = 'rejected';
    const report = buildDiagnosticsReport({
      generatedAtUnixMs: Date.now(),
      application: {mode: this.mode, apiVersion: this.apiVersion},
      controlPlane: {
        core: this.systemStatus.core,
        smithproxy: this.systemStatus.smithproxy,
        checkedAtUnixMs: this.systemStatus.checkedAtUnixMs,
        lastSuccessAtUnixMs: this.systemStatus.lastSuccessAtUnixMs,
        latencyMs: this.systemStatus.latencyMs,
        totalProbes: this.systemStatus.totalProbes,
        consecutiveFailures: this.systemStatus.consecutiveFailures,
        availabilitySamples: this.systemStatus.availabilitySamples,
        availabilitySuccessful: this.systemStatus.availabilitySuccessful,
      },
      gateway: {
        mode: this.gatewaySession?.mode ?? 'unknown',
        authenticated: this.gatewaySession?.authenticated ?? null,
        state: gatewayState,
      },
      capabilities: {
        bootstrapState: this.capabilityBootstrapState,
        checkedAtUnixMs: this.capabilityCheckedAtUnixMs,
        lastSuccessAtUnixMs: this.capabilityLastSuccessAtUnixMs,
        enabledFeatureCount: this.enabledCapabilityCount(),
        configRead: this.configReadAvailable,
        configWrite: this.configWriteAvailable,
        drafts: this.draftAvailable,
        draftPreflight: this.draftPreflightAvailable,
        jobs: this.jobsAvailable,
        eventsAvailable: this.eventsAvailable,
        alertsAvailable: this.alertsAvailable,
        auditAvailable: this.auditAvailable,
        metrics: this.metricsAvailable,
        sessionActivity: this.sessionActivityAvailable,
        tlsMonitoring: this.tlsMonitoringAvailable,
        neighborMonitoring: this.neighborMonitoringAvailable,
        interfaceMonitoring: this.interfaceMonitoringAvailable,
        configTransaction: this.transactionCapabilityState,
      },
      runtime: {
        state: this.runtimeMetrics.state,
        checkedAtUnixMs: this.runtimeMetrics.checkedAtUnixMs,
        lastSuccessAtUnixMs: this.runtimeMetrics.lastSuccessAtUnixMs,
        workers: this.runtimeMetrics.totals.workers,
        sessionsTotal: this.runtimeMetrics.totals.sessionsTotal,
        sessionsActive: this.runtimeMetrics.totals.sessionsActive,
        bytesUp: this.runtimeMetrics.totals.bytesUp,
        bytesDown: this.runtimeMetrics.totals.bytesDown,
        listenerCount: this.runtimeMetrics.listeners.length,
      },
      sessionActivity: {
        state: this.sessionActivity.state,
        checkedAtUnixMs: this.sessionActivity.checkedAtUnixMs,
        lastSuccessAtUnixMs: this.sessionActivity.lastSuccessAtUnixMs,
        total: this.sessionActivity.total,
        speedUp: this.sessionActivity.speedUp,
        speedDown: this.sessionActivity.speedDown,
        protocolCount: this.sessionActivity.protocols.length,
      },
      tlsCache: {
        state: this.tlsCache.state,
        checkedAtUnixMs: this.tlsCache.checkedAtUnixMs,
        lastSuccessAtUnixMs: this.tlsCache.lastSuccessAtUnixMs,
        size: this.tlsCache.size,
        capacity: this.tlsCache.capacity,
      },
      neighbors: {
        state: this.neighbors.state,
        checkedAtUnixMs: this.neighbors.checkedAtUnixMs,
        lastSuccessAtUnixMs: this.neighbors.lastSuccessAtUnixMs,
        hostsTotal: this.neighbors.hostsTotal,
        activeToday: this.neighbors.activeToday,
        activeWeek: this.neighbors.activeWeek,
        taggedHosts: this.neighbors.taggedHosts,
        observations: this.neighbors.observations,
        bytesUp: this.neighbors.bytesUp,
        bytesDown: this.neighbors.bytesDown,
      },
      interfaces: {
        state: this.interfaces.state,
        checkedAtUnixMs: this.interfaces.checkedAtUnixMs,
        lastSuccessAtUnixMs: this.interfaces.lastSuccessAtUnixMs,
        generation: this.interfaces.generation,
        synchronizationRunning: this.interfaces.synchronizationRunning,
        synchronizationAttempts: this.interfaces.synchronizationAttempts,
        synchronizationSuccesses: this.interfaces.synchronizationSuccesses,
        synchronizationErrors: this.interfaces.synchronizationErrors,
        eventDatagrams: this.interfaces.eventDatagrams,
        changedEventDatagrams: this.interfaces.changedEventDatagrams,
        interfaces: this.interfaces.interfaces,
        addresses: this.interfaces.addresses,
        ipv4Addresses: this.interfaces.ipv4Addresses,
        ipv6Addresses: this.interfaces.ipv6Addresses,
        lastErrorCode: this.interfaces.lastErrorCode,
      },
      operations: {
        eventStream: this.eventStreamState,
        eventStreamConnectedAtUnixMs: this.eventStreamConnectedAtUnixMs,
        eventStreamLastMessageAtUnixMs: this.eventStreamLastMessageAtUnixMs,
        eventStreamLastDisconnectAtUnixMs: this.eventStreamLastDisconnectAtUnixMs,
        eventStreamReconnectCount: this.eventStreamReconnectCount,
        eventCount: this.operationalEvents.events.length,
        activeAlertCount: this.operationalAlerts.alerts.length,
        auditEntryCount: this.managementAudit.entries.length,
        jobCount: this.backendJobs.jobs.length,
        activeJobCount: this.backendJobs.jobs.filter(job =>
          job.state === 'queued' || job.state === 'running' || job.state === 'cancelling').length,
        failedJobCount: this.backendJobs.jobs.filter(job => job.state === 'failed').length,
      },
      configuration: {
        source: this.snapshot?.source ?? 'unavailable',
        state: this.snapshot?.state ?? 'unknown',
        draftChangeCount: this.draftChangeCount,
      },
    });
    const url = URL.createObjectURL(new Blob([serializeDiagnosticsReport(report)], {type: 'application/json'}));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'smithproxy-gui-diagnostics.json';
    anchor.hidden = true;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  private async loadConfiguration(): Promise<void> {
    try {
      const preview = await this.previewClient.loadSnapshot();
      if (!this.configReadAvailable && this.snapshot?.source !== 'live') {
        this.snapshot = preview;
        this.restoreDrawerRoute();
      }
      await this.loadCapabilities();
    } catch (error) {
      this.loadingError = error instanceof Error ? error.message : 'Unable to load configuration.';
    }
  }

  private applyDraft(snapshot: DraftSnapshot): void {
    const previousVersion = this.draftVersion;
    this.workspaceDraft = snapshot;
    this.draftVersion = snapshot.version;
    const operationCount = draftOperationCount(snapshot);
    this.draftChangeCount = operationCount;
    const preflight = this.draftPreflight;
    if (!preflight || preflight.draftVersion !== snapshot.version ||
        preflight.changeCount !== operationCount) {
      this.draftPreflight = undefined;
    }
    const validation = this.draftValidation;
    if (!validation || validation.draftVersion !== snapshot.version ||
        validation.baseRevision !== snapshot.baseRevision ||
        validation.validatedOperations !== operationCount) {
      this.draftValidation = undefined;
    }
    if (previousVersion !== snapshot.version) {
      this.draftValidationError = undefined;
      this.draftCommitArmed = false;
      this.draftCommitError = undefined;
      this.draftCommitResult = undefined;
      this.draftRemovalArmedKey = undefined;
    }
    if (operationCount === 0) this.discardDraftArmed = false;
    const objects = new Set<string>();
    for (const change of snapshot.changes) {
      const policy = /^policy\.\[(\d+)\]\./u.exec(change.path);
      if (policy) {
        const item = this.snapshot?.policies[Number(policy[1])];
        if (item) objects.add(`policy:${item.id}`);
      }
      const address = /^address_objects\.\[(\d+)\]\./u.exec(change.path);
      if (address) {
        const item = this.snapshot?.addresses[Number(address[1])];
        if (item) objects.add(`address:${item.id}`);
      }
      const port = /^port_objects\.\[(\d+)\]\./u.exec(change.path);
      if (port) {
        const item = this.snapshot?.ports[Number(port[1])];
        if (item) objects.add(`port:${item.id}`);
      }
      const protocol = /^proto_objects\.\[(\d+)\]\./u.exec(change.path);
      if (protocol) {
        const item = this.snapshot?.protocols[Number(protocol[1])];
        if (item) objects.add(`protocol:${item.id}`);
      }
      const routing = /^routing\.\[(\d+)\]\./u.exec(change.path);
      if (routing) {
        const item = this.snapshot?.profiles.filter(profile => profile.routing !== null)[Number(routing[1])];
        if (item) objects.add(`profile:${item.id}`);
      }
      const detection = /^detection_profiles\.\[(\d+)\]\./u.exec(change.path);
      if (detection) {
        const item = this.snapshot?.profiles.filter(profile => profile.detection !== null)[Number(detection[1])];
        if (item) objects.add(`profile:${item.id}`);
      }
      const dns = /^alg_dns_profiles\.\[(\d+)\]\./u.exec(change.path);
      if (dns) {
        const item = this.snapshot?.profiles.filter(profile => profile.dns !== null)[Number(dns[1])];
        if (item) objects.add(`profile:${item.id}`);
      }
      const tls = /^tls_profiles\.\[(\d+)\]\./u.exec(change.path);
      if (tls) {
        const item = this.snapshot?.profiles.filter(profile => profile.tls !== null)[Number(tls[1])];
        if (item) objects.add(`profile:${item.id}`);
      }
      const content = /^content_profiles\.\[(\d+)\]\./u.exec(change.path);
      if (content) {
        const item = this.snapshot?.profiles.filter(profile => profile.content !== null)[Number(content[1])];
        if (item) {
          objects.add(`profile:${item.id}`);
          const rule = /^content_profiles\.\[\d+\]\.content_rules\.\[(\d+)\]\./u.exec(change.path);
          const contentRule = rule ? item.content?.rules[Number(rule[1])] : undefined;
          if (contentRule) objects.add(`content-rule:${contentRule.id}`);
        }
      }
      const ssh = /^ssh_profiles\.\[(\d+)\]\./u.exec(change.path);
      if (ssh) {
        const item = this.snapshot?.profiles.filter(profile => profile.ssh !== null)[Number(ssh[1])];
        if (item) objects.add(`profile:${item.id}`);
      }
      const script = /^script_profiles\.\[(\d+)\]\./u.exec(change.path);
      if (script) {
        const item = this.snapshot?.profiles.filter(profile => profile.script !== null)[Number(script[1])];
        if (item) objects.add(`profile:${item.id}`);
      }
      const authentication = /^auth_profiles\.\[(\d+)\]\./u.exec(change.path);
      if (authentication) {
        const item = this.snapshot?.profiles.filter(profile => profile.authentication !== null)[Number(authentication[1])];
        if (item) objects.add(`profile:${item.id}`);
      }
      const authority = /^tls_ca\.\[(\d+)\]\./u.exec(change.path);
      if (authority) {
        const item = this.snapshot?.securityAssets?.certificateAuthorities[Number(authority[1])];
        if (item) objects.add(`authority:${item.id}`);
      }
      const signature = /^(starttls|detection)_signatures\.\[(\d+)\](?:\.flow\.\[(\d+)\])?\./u
        .exec(change.path);
      if (signature) {
        const item = this.snapshot?.securityAssets?.signatures
          .filter(candidate => candidate.kind === signature[1])[Number(signature[2])];
        if (item) {
          objects.add(`signature:${item.id}`);
          const step = signature[3] === undefined ? undefined : item.flow[Number(signature[3])];
          if (step) objects.add(`signature-flow:${step.id}`);
        }
      }
      if (change.path.startsWith('settings.')) objects.add('settings:settings');
      if (change.path.startsWith('debug.')) objects.add('settings:settings');
      if (change.path.startsWith('captures.')) objects.add('captures:captures');
    }
    for (const operation of snapshot.structuralOperations) {
      if (operation.op === 'create' && operation.collection === 'address_objects') {
        objects.add(`address-create:${operation.localId}`);
      }
      if (operation.op === 'create' && operation.collection === 'policy') {
        objects.add(`policy-create:${operation.localId}`);
      }
      if (operation.op === 'create' && operation.collection === 'port_objects') {
        objects.add(`port-create:${operation.localId}`);
      }
      if (operation.op === 'create' && operation.collection === 'proto_objects') {
        objects.add(`protocol-create:${operation.localId}`);
      }
      if (operation.op === 'delete') {
        const kind = operation.collection === 'policy' ? 'policy'
          : operation.collection === 'address_objects' ? 'address'
            : operation.collection === 'port_objects' ? 'port'
              : operation.collection === 'proto_objects' ? 'protocol' : undefined;
        if (kind) objects.add(`${kind}:${operation.entityId}`);
      }
    }
    this.draftObjects = objects;
  }

  private draftTargetForPath(path: string): DrawerEntry | undefined {
    if (path.startsWith('settings.') || path.startsWith('debug.')) {
      return {kind: 'settings', id: 'settings', title: 'System settings'};
    }
    if (path.startsWith('captures.')) {
      return {kind: 'captures', id: 'captures', title: 'Capture settings'};
    }

    const indexed = <T>(pattern: RegExp, items: ReadonlyArray<T>): T | undefined => {
      const match = pattern.exec(path);
      return match ? items[Number(match[1])] : undefined;
    };
    const policy = indexed(/^policy\.\[(\d+)\]\./u, this.snapshot?.policies ?? []);
    if (policy) return {kind: 'policy', id: policy.id, title: this.policyDisplayName(policy)};
    const address = indexed(/^address_objects\.\[(\d+)\]\./u, this.snapshot?.addresses ?? []);
    if (address) return {kind: 'address', id: address.id, title: this.addressDisplayName(address)};
    const port = indexed(/^port_objects\.\[(\d+)\]\./u, this.snapshot?.ports ?? []);
    if (port) return {kind: 'port', id: port.id, title: this.portDisplayName(port)};
    const protocol = indexed(/^proto_objects\.\[(\d+)\]\./u, this.snapshot?.protocols ?? []);
    if (protocol) return {kind: 'protocol', id: protocol.id, title: this.protocolDisplayName(protocol)};
    const authority = indexed(
      /^tls_ca\.\[(\d+)\]\./u, this.snapshot?.securityAssets?.certificateAuthorities ?? [],
    );
    if (authority) {
      return {kind: 'authority', id: authority.id, title: this.authorityDisplayName(authority.id, authority.name)};
    }

    const signatureMatch = /^(?:starttls|detection)_signatures\.\[(\d+)\](?:\.flow\.\[(\d+)\])?\./u
      .exec(path);
    if (signatureMatch) {
      const kind = path.startsWith('starttls_') ? 'starttls' : 'detection';
      const signature = this.snapshot?.securityAssets?.signatures
        .filter(item => item.kind === kind)[Number(signatureMatch[1])];
      const flowIndex = signatureMatch[2];
      const step = flowIndex === undefined ? undefined : signature?.flow[Number(flowIndex)];
      if (step) {
        return {kind: 'signature-flow', id: step.id, title: `Flow ${step.side.toUpperCase()}`};
      }
      if (signature) {
        return {kind: 'signature', id: signature.id, title: this.signatureDisplayName(signature.id, signature.name)};
      }
    }

    const profileSections: ReadonlyArray<{
      pattern: RegExp;
      matches: (profile: ProfileObject) => boolean;
    }> = [
      {pattern: /^routing\.\[(\d+)\]\./u, matches: profile => profile.routing !== null},
      {pattern: /^detection_profiles\.\[(\d+)\]\./u, matches: profile => profile.detection !== null},
      {pattern: /^alg_dns_profiles\.\[(\d+)\]\./u, matches: profile => profile.dns !== null},
      {pattern: /^tls_profiles\.\[(\d+)\]\./u, matches: profile => profile.tls !== null},
      {pattern: /^content_profiles\.\[(\d+)\]\./u, matches: profile => profile.content !== null},
      {pattern: /^ssh_profiles\.\[(\d+)\]\./u, matches: profile => profile.ssh !== null},
      {pattern: /^script_profiles\.\[(\d+)\]\./u, matches: profile => profile.script !== null},
      {pattern: /^auth_profiles\.\[(\d+)\]\./u, matches: profile => profile.authentication !== null},
    ];
    for (const section of profileSections) {
      const match = section.pattern.exec(path);
      if (!match) continue;
      const profile = this.snapshot?.profiles.filter(section.matches)[Number(match[1])];
      if (!profile) return undefined;
      const ruleMatch = /^content_profiles\.\[\d+\]\.content_rules\.\[(\d+)\]\./u.exec(path);
      const rule = ruleMatch ? profile.content?.rules[Number(ruleMatch[1])] : undefined;
      return rule
        ? {kind: 'content-rule', id: rule.id, title: `Content rule ${Number(ruleMatch![1]) + 1}`}
        : {kind: 'profile', id: profile.id, title: this.profileDisplayName(profile)};
    }
    return undefined;
  }

  private async loadDraft(): Promise<void> {
    if (!this.draftAvailable || !this.draftClient) return;
    const accessEpoch = this.configurationAccessEpoch;
    try {
      const draft = await this.draftClient.load();
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      this.applyDraft(draft);
      this.draftError = undefined;
      await this.loadDraftPreflight();
    } catch (error) {
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      this.draftError = error instanceof Error ? error.message : 'Workspace draft is unavailable.';
    }
  }

  private async loadDraftPreflight(): Promise<void> {
    if (!this.draftPreflightAvailable || !this.draftClient) return;
    const accessEpoch = this.configurationAccessEpoch;
    try {
      const preflight = await this.draftClient.preflight();
      if (!this.draftAccessIsCurrent(accessEpoch) || !this.draftPreflightAvailable) return;
      if (preflight.draftVersion !== this.draftVersion ||
          preflight.changeCount !== this.draftChangeCount) {
        throw new Error('Draft preflight does not match the current workspace draft.');
      }
      this.draftPreflight = preflight;
      this.draftPreflightError = undefined;
    } catch (error) {
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      this.draftPreflight = undefined;
      this.draftPreflightError = error instanceof Error ? error.message : 'Draft preflight is unavailable.';
    }
  }

  private async validateDraft(): Promise<void> {
    const preflight = this.draftPreflight;
    if (!this.draftClient || !preflight?.validationAvailable || this.draftChangeCount === 0 ||
        this.draftValidating || this.draftSaving || this.draftCommitting ||
        !preflight.baseRevision) return;
    const expectedVersion = this.draftVersion;
    const expectedChanges = this.draftChangeCount;
    const expectedRevision = preflight.baseRevision;
    const accessEpoch = this.configurationAccessEpoch;
    this.draftValidating = true;
    this.draftValidation = undefined;
    this.draftValidationError = undefined;
    try {
      const validation = await this.draftClient.validate(expectedVersion);
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      if (this.draftVersion !== expectedVersion || validation.draftVersion !== expectedVersion ||
          validation.baseRevision !== expectedRevision ||
          validation.validatedOperations !== expectedChanges) {
        throw new Error('Smithproxy validation does not match the current workspace draft.');
      }
      this.draftValidation = validation;
    } catch (error) {
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      const message = error instanceof Error ? error.message : 'Smithproxy validation is unavailable.';
      await this.loadDraft();
      this.draftValidationError = message;
    } finally {
      if (accessEpoch === this.configurationAccessEpoch) this.draftValidating = false;
    }
  }

  private async commitDraft(): Promise<void> {
    const preflight = this.draftPreflight;
    const validation = this.draftValidation;
    const validationMatches = validation &&
      validation.draftVersion === this.draftVersion &&
      validation.baseRevision === preflight?.baseRevision &&
      validation.validatedOperations === this.draftChangeCount;
    if (!this.configWriteAvailable || !this.draftClient || !preflight?.commitAvailable ||
        !validationMatches || this.draftChangeCount === 0 || this.draftCommitting ||
        this.draftSaving || this.draftValidating) return;
    if (!this.draftCommitArmed) {
      this.draftCommitArmed = true;
      this.draftCommitError = undefined;
      return;
    }

    const expectedVersion = this.draftVersion;
    const expectedRevision = preflight.baseRevision;
    const expectedOperations = this.draftChangeCount;
    const accessEpoch = this.configurationAccessEpoch;
    this.draftCommitting = true;
    this.draftCommitArmed = false;
    this.draftCommitError = undefined;
    this.draftCommitResult = undefined;
    try {
      const result = await this.draftClient.commit(expectedVersion);
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      if (result.committedDraftVersion !== expectedVersion ||
          result.previousRevision !== expectedRevision ||
          result.committedOperations !== expectedOperations) {
        throw new Error('Smithproxy commit does not match the validated workspace draft.');
      }
      const current = await this.draftClient.load();
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      if (current.version !== result.draftVersion || current.baseRevision !== result.revision ||
          draftOperationCount(current) !== 0) {
        throw new Error('Committed draft finalization could not be verified.');
      }
      this.applyDraft(current);
      this.draftCommitResult = result;
      this.draftValidation = undefined;
      await this.loadDraftPreflight();
      if (this.jobsAvailable && this.systemClient) {
        const monitoringEpoch = this.monitoringAccessEpoch;
        try {
          const jobs = await this.systemClient.jobs();
          if (monitoringEpoch === this.monitoringAccessEpoch && this.jobsAvailable) {
            this.backendJobs = jobs;
            this.jobsError = undefined;
          }
        } catch (error) {
          if (monitoringEpoch === this.monitoringAccessEpoch && this.jobsAvailable) {
            this.jobsError = error instanceof Error ? error.message : 'Backend jobs are unavailable.';
          }
        }
      }
      this.configRefreshDeferred = true;
      this.nextConfigRefreshAt = 0;
    } catch (error) {
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      const message = error instanceof Error ? error.message : 'Atomic commit could not be confirmed.';
      await this.loadDraft();
      this.draftCommitError = message;
    } finally {
      if (accessEpoch === this.configurationAccessEpoch) this.draftCommitting = false;
    }
  }

  private async discardDraft(): Promise<void> {
    if (!this.draftAvailable || !this.draftClient || this.draftChangeCount === 0 ||
        this.draftCommitting) return;
    if (!this.discardDraftArmed) {
      this.discardDraftArmed = true;
      return;
    }
    this.draftSaving = true;
    const accessEpoch = this.configurationAccessEpoch;
    this.draftError = undefined;
    try {
      const draft = await this.draftClient.clear(this.draftVersion);
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      this.applyDraft(draft);
      await this.loadDraftPreflight();
    } catch (error) {
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      const message = error instanceof Error ? error.message : 'Workspace draft could not be discarded.';
      await this.loadDraft();
      this.draftError = message;
    } finally {
      if (accessEpoch === this.configurationAccessEpoch) {
        this.draftSaving = false;
        this.discardDraftArmed = false;
        if (this.draftChangeCount === 0) void this.refreshConfiguration(true);
      }
    }
  }

  private async removeDraftChange(path: string): Promise<void> {
    if (!this.draftAvailable || !this.draftClient || this.draftSaving || this.draftCommitting) return;
    this.draftSaving = true;
    const accessEpoch = this.configurationAccessEpoch;
    this.draftError = undefined;
    try {
      const draft = await this.draftClient.remove(this.draftVersion, path);
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      this.applyDraft(draft);
      await this.loadDraftPreflight();
    } catch (error) {
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      const message = error instanceof Error ? error.message : 'Draft change could not be removed.';
      await this.loadDraft();
      this.draftError = message;
    } finally {
      if (accessEpoch === this.configurationAccessEpoch) this.draftSaving = false;
    }
  }

  private async removeDraftOperation(localId: string): Promise<void> {
    if (!this.draftAvailable || !this.draftClient || this.draftSaving || this.draftCommitting) return;
    this.draftSaving = true;
    const accessEpoch = this.configurationAccessEpoch;
    this.draftError = undefined;
    try {
      const draft = await this.draftClient.removeOperation(this.draftVersion, localId);
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      this.applyDraft(draft);
      await this.loadDraftPreflight();
    } catch (error) {
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      const message = error instanceof Error ? error.message : 'Structural draft operation could not be removed.';
      await this.loadDraft();
      this.draftError = message;
    } finally {
      if (accessEpoch === this.configurationAccessEpoch) this.draftSaving = false;
    }
  }

  private openDraftStructuralOperation(localId: string, origin: HTMLElement): void {
    const operation = this.workspaceDraft?.structuralOperations.find(item => item.localId === localId);
    if (operation?.op !== 'create' || ![
      'address_objects', 'port_objects', 'proto_objects', 'policy',
    ].includes(operation.collection)) return;
    const kind = operation.collection === 'policy' ? 'policy-create'
      : operation.collection === 'address_objects' ? 'address-create'
        : operation.collection === 'port_objects' ? 'port-create' : 'protocol-create';
    const fallback = operation.collection === 'policy' ? 'New policy'
      : operation.collection === 'address_objects' ? 'New address object'
        : operation.collection === 'port_objects' ? 'New port object' : 'New protocol object';
    this.openObjectDrawer({
      kind,
      id: operation.localId,
      title: String(operation.fields['name'] ?? fallback),
    }, origin);
  }

  private draftPathsForDrawer(entry: Pick<DrawerEntry, 'kind' | 'id'>): ReadonlyArray<string> {
    const key = this.drawerKey(entry);
    return (this.workspaceDraft?.changes ?? [])
      .filter(change => {
        const target = this.draftTargetForPath(change.path);
        return target !== undefined && this.drawerKey(target) === key;
      })
      .map(change => change.path);
  }

  private async removeDrawerDraftChanges(entry: DrawerEntry): Promise<void> {
    if (!this.draftAvailable || !this.draftClient || this.draftSaving || this.draftCommitting ||
        this.dirtyDrawerKeys.has(this.drawerKey(entry))) return;
    const paths = this.draftPathsForDrawer(entry);
    if (paths.length === 0) return;
    const key = this.drawerKey(entry);
    if (this.draftRemovalArmedKey !== key) {
      this.draftRemovalArmedKey = key;
      return;
    }
    this.draftSaving = true;
    const accessEpoch = this.configurationAccessEpoch;
    this.draftError = undefined;
    try {
      const draft = await this.draftClient.removeMany(this.draftVersion, paths);
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      this.applyDraft(draft);
      await this.loadDraftPreflight();
      this.markDrawerSaved(entry);
    } catch (error) {
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      const message = error instanceof Error ? error.message : 'Editor draft changes could not be removed.';
      await this.loadDraft();
      this.draftError = message;
    } finally {
      if (accessEpoch === this.configurationAccessEpoch) {
        this.draftSaving = false;
        this.draftRemovalArmedKey = undefined;
      }
    }
  }

  private structuralDeleteTarget(entry: DrawerEntry): {
    collection: DraftDeleteOperation['collection'];
    entityId: string;
    label: string;
    usageCount: number;
  } | undefined {
    if (!this.snapshot) return undefined;
    if (entry.kind === 'policy') {
      const policy = this.snapshot.policies.find(item => item.id === entry.id);
      return policy
        ? {collection: 'policy', entityId: policy.id, label: 'policy', usageCount: 0}
        : undefined;
    }
    if (entry.kind === 'address') {
      const address = this.snapshot.addresses.find(item => item.id === entry.id);
      return address
        ? {collection: 'address_objects', entityId: address.id,
          label: 'address object', usageCount: address.usedBy.length}
        : undefined;
    }
    if (entry.kind === 'port') {
      const port = this.snapshot.ports.find(item => item.id === entry.id);
      return port
        ? {collection: 'port_objects', entityId: port.id, label: 'port object', usageCount: port.usedBy.length}
        : undefined;
    }
    if (entry.kind === 'protocol') {
      const protocol = this.snapshot.protocols.find(item => item.id === entry.id);
      return protocol
        ? {collection: 'proto_objects', entityId: protocol.id,
          label: 'protocol object', usageCount: protocol.usedBy.length}
        : undefined;
    }
    return undefined;
  }

  private pendingStructuralDelete(target: {collection: string; entityId: string}): boolean {
    return this.workspaceDraft?.structuralOperations.some(operation =>
      operation.op === 'delete' && operation.collection === target.collection &&
      operation.entityId === target.entityId) ?? false;
  }

  private structuralDeleteBlocker(entry: DrawerEntry, target: {
    collection: string;
    entityId: string;
    usageCount: number;
  }): string | undefined {
    if (!this.structuralDraftsAvailable) return 'Stable structural transactions are unavailable.';
    if (this.dirtyDrawerKeys.has(this.drawerKey(entry))) return 'Discard or save unsaved editor changes first.';
    if (this.draftPathsForDrawer(entry).length > 0) return 'Remove pending field edits before deleting this entry.';
    if (target.usageCount > 0) {
      return `This object is referenced by ${target.usageCount} configuration ${target.usageCount === 1 ? 'entry' : 'entries'}.`;
    }
    if (this.workspaceDraft?.structuralOperations.some(operation =>
      operation.collection === target.collection &&
      ('entityId' in operation ? operation.entityId === target.entityId : false))) {
      return this.pendingStructuralDelete(target)
        ? 'Deletion is already pending in the workspace draft.'
        : 'Another structural operation already targets this entry.';
    }
    return undefined;
  }

  private async deleteStructuralEntry(entry: DrawerEntry): Promise<void> {
    const target = this.structuralDeleteTarget(entry);
    if (!target || !this.draftClient || this.draftSaving || this.draftCommitting) return;
    const blocker = this.structuralDeleteBlocker(entry, target);
    if (blocker) {
      this.drawerError = blocker;
      return;
    }
    const key = this.drawerKey(entry);
    if (this.structuralDeleteArmedKey !== key) {
      this.structuralDeleteArmedKey = key;
      this.drawerError = `Confirm deletion of this ${target.label}.`;
      return;
    }
    this.draftSaving = true;
    this.drawerError = undefined;
    this.draftError = undefined;
    const accessEpoch = this.configurationAccessEpoch;
    try {
      const draft = await this.draftClient.upsertOperation(this.draftVersion, {
        op: 'delete', localId: `delete-${entry.kind}-${crypto.randomUUID()}`,
        collection: target.collection, entityId: target.entityId,
      });
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      this.applyDraft(draft);
      await this.loadDraftPreflight();
      this.markDrawerSaved(entry);
      this.structuralDeleteArmedKey = undefined;
      const index = this.drawerStore.entries.findIndex(item => this.drawerKey(item) === key);
      if (index >= 0) this.closeDrawer(index);
    } catch (error) {
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      const message = error instanceof Error ? error.message : 'The entry could not be deleted from the draft.';
      await this.loadDraft();
      this.drawerError = message;
    } finally {
      if (accessEpoch === this.configurationAccessEpoch) {
        this.draftSaving = false;
        this.structuralDeleteArmedKey = undefined;
      }
    }
  }

  private draftValueSummary(path: string, value: DraftScalar): string {
    if (value === '[redacted:clear]') return 'Cleared · redacted';
    if (value === '[redacted:replace]') return 'Replaced · redacted';
    if (typeof value === 'string') {
      const redactedCollection = /^\[redacted:replace:(\d+)]$/.exec(value);
      if (redactedCollection) {
        const count = Number(redactedCollection[1]);
        return `Replaced · redacted · ${count} item${count === 1 ? '' : 's'}`;
      }
    }
    const sensitivePaths = new Set([
      'settings.webhook.url', 'settings.syslog_server', 'settings.write_payload_dir',
      'settings.log_file', 'settings.sslkeylog_file', 'settings.certs_path',
      'settings.certs_ca_key_password', 'settings.certs_ctlog', 'settings.ca_bundle_path',
      'settings.ca_bundle_file', 'settings.admin.group', 'settings.messages_dir',
      'settings.write_payload_file_prefix', 'settings.write_payload_file_suffix',
      'settings.cli.enable_password', 'settings.web_rating.wot_key', 'settings.http_api.keys',
      'settings.http_api.bind_address', 'settings.http_api.bind_interface',
      'settings.webhook.sift_url', 'settings.webhook.sift_tenant_id',
      'settings.webhook.sift_instance_id', 'settings.webhook.hostid',
      'settings.webhook.bind_interface',
      'captures.local.dir', 'captures.local.file_prefix', 'captures.local.file_suffix',
      'captures.remote.tun_dst', 'captures.remote.bind_interface',
    ]);
    const indexedSensitivePath =
      (path.startsWith('ssh_profiles.[') && path.endsWith('].host_key')) ||
      (path.startsWith('script_profiles.[') && path.endsWith('].script-file')) ||
      (path.startsWith('tls_profiles.[') && path.endsWith('].sni_filter_bypass')) ||
      (path.startsWith('content_profiles.[') && path.endsWith('].rules_session_filter')) ||
      (path.startsWith('content_profiles.[') && path.includes('].content_rules.[') &&
        (path.endsWith('].match') || path.endsWith('].replace'))) ||
      (path.startsWith('tls_ca.[') && path.endsWith('].path')) ||
      ((path.startsWith('starttls_signatures.[') || path.startsWith('detection_signatures.[')) &&
        path.endsWith('].signature'));
    if (sensitivePaths.has(path) || indexedSensitivePath) {
      if (value === '' || (Array.isArray(value) && value.length === 0)) return 'Cleared · redacted';
      const count = Array.isArray(value) ? ` · ${value.length} item${value.length === 1 ? '' : 's'}` : '';
      return `Replaced · redacted${count}`;
    }
    if (Array.isArray(value)) {
      const preview = value.slice(0, 3).join(', ');
      return `${value.length} item${value.length === 1 ? '' : 's'}${preview ? ` · ${preview}` : ''}${value.length > 3 ? ', …' : ''}`;
    }
    const text = String(value);
    return text.length > 160 ? `${text.slice(0, 157)}…` : text;
  }

  private policyDisplayName(policy: PolicySummary): string {
    const index = this.snapshot?.policies.findIndex(item => item.id === policy.id) ?? -1;
    return index < 0 ? policy.name : this.presentedValue(`policy.[${index}].name`, policy.name);
  }

  private addressDisplayName(address: AddressObject): string {
    const index = this.snapshot?.addresses.findIndex(item => item.id === address.id) ?? -1;
    return index < 0 ? address.name : this.presentedValue(`address_objects.[${index}].name`, address.name);
  }

  private portDisplayName(port: PortObject): string {
    const index = this.snapshot?.ports.findIndex(item => item.id === port.id) ?? -1;
    return index < 0 ? port.name : this.presentedValue(`port_objects.[${index}].name`, port.name);
  }

  private protocolDisplayName(protocol: ProtocolObject): string {
    const index = this.snapshot?.protocols.findIndex(item => item.id === protocol.id) ?? -1;
    return index < 0 ? protocol.name : this.presentedValue(`proto_objects.[${index}].name`, protocol.name);
  }

  private profileDisplayName(profile: ProfileObject): string {
    const prefix = this.profileOriginPrefixes().get(profile.id);
    return prefix ? this.presentedValue(`${prefix}name`, profile.name) : profile.name;
  }

  private authorityDisplayName(id: string, fallback: string): string {
    const index = this.snapshot?.securityAssets?.certificateAuthorities.findIndex(item => item.id === id) ?? -1;
    return index < 0 ? fallback : this.presentedValue(`tls_ca.[${index}].name`, fallback);
  }

  private signatureDisplayName(id: string, fallback: string): string {
    const signature = this.snapshot?.securityAssets?.signatures.find(item => item.id === id);
    if (!signature) return fallback;
    const index = this.snapshot!.securityAssets!.signatures
      .filter(item => item.kind === signature.kind).findIndex(item => item.id === id);
    return index < 0 ? fallback : this.presentedValue(`${signature.kind}_signatures.[${index}].name`, fallback);
  }

  private openPolicy(policy: PolicySummary, origin?: HTMLElement): void {
    this.openObjectDrawer({kind: 'policy', id: policy.id, title: this.policyDisplayName(policy)}, origin);
  }

  private openAddress(id: string, origin?: HTMLElement): void {
    const address = this.snapshot?.addresses.find(item => item.id === id);
    if (!address) return;
    this.openObjectDrawer({kind: 'address', id: address.id, title: this.addressDisplayName(address)}, origin);
  }

  private openNewAddress(origin?: HTMLElement): void {
    if (!this.structuralDraftsAvailable) return;
    const localId = `create-address-${crypto.randomUUID()}`;
    this.openObjectDrawer({
      kind: 'address-create', id: localId, title: 'New address object',
    }, origin);
  }

  private openNewPort(origin?: HTMLElement): void {
    if (!this.structuralDraftsAvailable) return;
    const localId = `create-port-${crypto.randomUUID()}`;
    this.openObjectDrawer({kind: 'port-create', id: localId, title: 'New port object'}, origin);
  }

  private openNewProtocol(origin?: HTMLElement): void {
    if (!this.structuralDraftsAvailable) return;
    const localId = `create-protocol-${crypto.randomUUID()}`;
    this.openObjectDrawer({kind: 'protocol-create', id: localId, title: 'New protocol object'}, origin);
  }

  private openNewPolicy(origin?: HTMLElement): void {
    if (!this.structuralDraftsAvailable) return;
    const localId = `create-policy-${crypto.randomUUID()}`;
    this.openObjectDrawer({kind: 'policy-create', id: localId, title: 'New policy'}, origin);
  }

  private openPort(id: string, origin?: HTMLElement): void {
    const port = this.snapshot?.ports.find(item => item.id === id);
    if (!port) return;
    this.openObjectDrawer({kind: 'port', id: port.id, title: this.portDisplayName(port)}, origin);
  }

  private openProtocol(id: string, origin?: HTMLElement): void {
    const protocol = this.snapshot?.protocols.find(item => item.id === id);
    if (!protocol) return;
    this.openObjectDrawer({kind: 'protocol', id: protocol.id, title: this.protocolDisplayName(protocol)}, origin);
  }

  private openProfile(id: string, origin?: HTMLElement): void {
    const profile = this.snapshot?.profiles.find(item => item.id === id);
    if (!profile) return;
    this.openObjectDrawer({kind: 'profile', id: profile.id, title: this.profileDisplayName(profile)}, origin);
  }

  private openUsage(reference: ConfigUsage, origin?: HTMLElement): void {
    if (reference.kind === 'policy') {
      const policy = this.snapshot?.policies.find(item => item.id === reference.id);
      if (policy) this.openPolicy(policy, origin);
      return;
    }
    const profile = this.snapshot?.profiles.find(item => item.id === reference.id && item.routing !== null);
    if (profile) this.openProfile(profile.id, origin);
  }

  private usageTargetAvailable(reference: ConfigUsage): boolean {
    if (reference.kind === 'policy') return Boolean(this.snapshot?.policies.some(item => item.id === reference.id));
    return Boolean(this.snapshot?.profiles.some(item => item.id === reference.id && item.routing !== null));
  }

  private openContentRule(id: string, origin?: HTMLElement): void {
    const profile = this.snapshot?.profiles.find(item => item.content?.rules.some(rule => rule.id === id));
    const index = profile?.content?.rules.findIndex(rule => rule.id === id) ?? -1;
    const rule = index < 0 ? undefined : profile?.content?.rules[index];
    if (!rule) return;
    this.openObjectDrawer({kind: 'content-rule', id: rule.id, title: `Content rule ${index + 1}`}, origin);
  }

  private openAuthority(id: string, origin?: HTMLElement): void {
    const authority = this.snapshot?.securityAssets?.certificateAuthorities.find(item => item.id === id);
    if (!authority) return;
    this.openObjectDrawer({
      kind: 'authority', id: authority.id, title: this.authorityDisplayName(authority.id, authority.name),
    }, origin);
  }

  private openSignature(id: string, origin?: HTMLElement): void {
    const signature = this.snapshot?.securityAssets?.signatures.find(item => item.id === id);
    if (!signature) return;
    this.openObjectDrawer({
      kind: 'signature', id: signature.id, title: this.signatureDisplayName(signature.id, signature.name),
    }, origin);
  }

  private openSignatureFlow(id: string, origin?: HTMLElement): void {
    const step = this.snapshot?.securityAssets?.signatures
      .flatMap(item => item.flow).find(item => item.id === id);
    if (!step) return;
    this.openObjectDrawer({kind: 'signature-flow', id: step.id, title: `Flow ${step.side.toUpperCase()}`}, origin);
  }

  private openSystemDrawer(kind: 'settings' | 'captures', origin?: HTMLElement): void {
    if ((kind === 'settings' && !this.snapshot?.settings) ||
        (kind === 'captures' && !this.snapshot?.captures)) return;
    this.openObjectDrawer({kind, id: kind, title: kind === 'settings' ? 'System settings' : 'Capture settings'}, origin);
  }

  private openObjectDrawer(entry: DrawerEntry, origin?: HTMLElement): void {
    this.draftRemovalArmedKey = undefined;
    const existing = this.drawerStore.entries.findIndex(
      item => item.kind === entry.kind && item.id === entry.id,
    );
    if (existing >= 0) {
      if (existing === this.drawerStore.entries.length - 1) {
        void this.updateComplete.then(() => this.focusActiveDrawer());
        return;
      }
      this.requestCloseDrawer(existing + 1);
      return;
    }
    if (!this.drawerStore.open(entry)) {
      this.drawerError = `Editor chain is limited to ${MAXIMUM_DRAWER_DEPTH} levels. Close an earlier editor to continue.`;
      return;
    }
    this.drawerError = undefined;
    this.pendingCloseIndex = undefined;
    this.drawerOrigins = [
      ...this.drawerOrigins.slice(0, this.drawerStore.entries.length - 1),
      ...(origin ? [origin] : []),
    ];
    this.focusMode = false;
    this.syncDrawers(true);
    void this.updateComplete.then(() => this.captureDrawerInitialChanges(entry));
  }

  private drawerKey(entry: Pick<DrawerEntry, 'kind' | 'id'>): string {
    return `${entry.kind}:${entry.id}`;
  }

  private draftScalarsEqual(left: DraftScalar, right: DraftScalar): boolean {
    if (!Array.isArray(left) || !Array.isArray(right)) return Object.is(left, right);
    return left.length === right.length && left.every((item, index) => Object.is(item, right[index]));
  }

  private captureDrawerInitialChanges(entry: DrawerEntry): void {
    if (!this.drawerStore.entries.some(item => this.drawerKey(item) === this.drawerKey(entry)) ||
        this.dirtyDrawerKeys.has(this.drawerKey(entry))) return;
    const changes = this.draftChanges(entry);
    if (!changes) return;
    this.drawerInitialChanges.set(
      this.drawerKey(entry),
      new Map(changes.map(change => [change.path, change.value])),
    );
  }

  private markDrawerDirty(entry: DrawerEntry, event: Event): void {
    const target = event.target;
    if (!(target instanceof HTMLInputElement || target instanceof HTMLSelectElement ||
          target instanceof HTMLTextAreaElement) || target.disabled ||
        ((target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) && target.readOnly)) {
      return;
    }
    const key = this.drawerKey(entry);
    if (this.draftRemovalArmedKey === key) this.draftRemovalArmedKey = undefined;
    if (this.structuralDeleteArmedKey === key) this.structuralDeleteArmedKey = undefined;
    if (!this.dirtyDrawerKeys.has(key)) {
      this.dirtyDrawerKeys = new Set(this.dirtyDrawerKeys).add(key);
    }
    if (target instanceof HTMLInputElement && target.dataset.referencePreview === 'true') {
      this.referencePreviewValues.set(`${key}|${target.id}`, target.value);
      this.requestUpdate();
    }
  }

  private clearReferencePreviews(entry: DrawerEntry): void {
    const prefix = `${this.drawerKey(entry)}|`;
    for (const key of this.referencePreviewValues.keys()) {
      if (key.startsWith(prefix)) this.referencePreviewValues.delete(key);
    }
  }

  private markDrawerSaved(entry: DrawerEntry): void {
    const key = this.drawerKey(entry);
    if (this.dirtyDrawerKeys.has(key)) {
      const remaining = new Set(this.dirtyDrawerKeys);
      remaining.delete(key);
      this.dirtyDrawerKeys = remaining;
    }
    this.clearReferencePreviews(entry);
    this.pendingCloseIndex = undefined;
  }

  private requestCloseDrawer(index: number): void {
    const dirty = this.drawerStore.entries.slice(index)
      .some(entry => this.dirtyDrawerKeys.has(this.drawerKey(entry)));
    if (!dirty) {
      this.closeDrawer(index);
      return;
    }
    this.pendingCloseIndex = index;
    void this.updateComplete.then(() => {
      this.renderRoot.querySelector<HTMLElement>('[data-keep-editing]')?.focus();
    });
  }

  private keepEditing(): void {
    this.pendingCloseIndex = undefined;
    void this.updateComplete.then(() => this.focusActiveDrawer());
  }

  private discardDrawerChanges(index: number): void {
    const remaining = new Set(this.dirtyDrawerKeys);
    for (const entry of this.drawerStore.entries.slice(index)) remaining.delete(this.drawerKey(entry));
    this.dirtyDrawerKeys = remaining;
    this.pendingCloseIndex = undefined;
    this.closeDrawer(index);
  }

  private closeDrawer(index: number): void {
    this.draftRemovalArmedKey = undefined;
    this.structuralDeleteArmedKey = undefined;
    const remainingDirty = new Set(this.dirtyDrawerKeys);
    for (const entry of this.drawerStore.entries.slice(index)) {
      remainingDirty.delete(this.drawerKey(entry));
      this.drawerInitialChanges.delete(this.drawerKey(entry));
      this.clearReferencePreviews(entry);
    }
    this.dirtyDrawerKeys = remainingDirty;
    this.pendingCloseIndex = undefined;
    const levels = this.drawerStore.entries.length - index;
    const returnFocus = this.drawerOrigins[index];
    this.drawerStore.closeFrom(index);
    this.drawerOrigins = this.drawerOrigins.slice(0, index);
    this.drawerError = undefined;
    this.focusMode = false;
    this.syncDrawers(false);
    if (this.drawers.length === 0 && this.configRefreshDeferred && this.draftChangeCount === 0) {
      void this.refreshConfiguration(true);
    }
    if (levels > 0 && this.drawerHistoryDepth >= levels) {
      this.drawerHistoryDepth -= levels;
      this.pendingReturnFocus = returnFocus;
      this.drawerHistoryNavigationPending = true;
      history.go(-levels);
    } else {
      this.replaceDrawerRoute();
      if (returnFocus?.isConnected) void this.updateComplete.then(() => returnFocus.focus());
    }
  }

  private syncDrawers(pushRoute: boolean): void {
    this.drawers = [...this.drawerStore.entries];
    if (pushRoute) {
      const hostState = typeof history.state === 'object' && history.state !== null ? history.state : {};
      history.pushState({...hostState, smithproxyGuiDrawer: true}, '', this.drawerUrl());
      this.drawerHistoryDepth += 1;
    }
    void this.updateComplete.then(() => this.focusActiveDrawer());
  }

  private drawerUrl(): string {
    return `${location.pathname}${drawerRouteSearch(location.search, this.drawerStore.entries)}${location.hash}`;
  }

  private replaceDrawerRoute(): void {
    history.replaceState(history.state, '', this.drawerUrl());
  }

  private restoreDrawerRoute(): void {
    if (!this.snapshot) return;
    const route = parseDrawerRoute(location.search);
    const hasRouteParameter = new URLSearchParams(location.search).has('edit');
    const openEntries = new Map(this.drawerStore.entries.map(entry => [
      `${entry.kind}:${entry.id}`,
      {id: entry.id, name: entry.title},
    ]));
    this.drawerStore.clear();
    this.drawerInitialChanges.clear();
    this.drawerOrigins = [];
    let valid = true;
    for (const entry of route) {
      const candidate = this.drawerCandidate(entry) ?? openEntries.get(`${entry.kind}:${entry.id}`);
      if (!candidate) { valid = false; break; }
      if (!this.drawerStore.open({kind: entry.kind, id: candidate.id, title: candidate.name})) {
        valid = false;
        break;
      }
    }
    if (!valid || (hasRouteParameter && route.length === 0)) {
      this.drawerStore.clear();
      const parameters = new URLSearchParams(location.search);
      parameters.delete('edit');
      const search = parameters.toString();
      history.replaceState(
        history.state,
        '',
        `${location.pathname}${search ? `?${search}` : ''}${location.hash}`,
      );
    }
    this.drawers = [...this.drawerStore.entries];
    if (this.drawers[0]?.kind === 'policy') this.activeSection = 'Policy';
    if (this.drawers[0] && ['settings', 'captures', 'authority', 'signature', 'signature-flow']
      .includes(this.drawers[0].kind)) {
      this.activeSection = 'System';
    }
    else if (this.drawers[0] && this.drawers[0].kind !== 'policy') this.activeSection = 'Objects';
    this.focusMode = false;
    void this.updateComplete.then(() => this.focusActiveDrawer());
    void this.updateComplete.then(() => {
      for (const entry of this.drawerStore.entries) this.captureDrawerInitialChanges(entry);
    });
  }

  private drawerCandidate(entry: Pick<DrawerEntry, 'kind' | 'id'>) {
    if (!this.snapshot) return undefined;
    if (entry.kind === 'policy') return this.snapshot.policies.find(item => item.id === entry.id);
    if (entry.kind === 'policy-create') {
      const operation = this.workspaceDraft?.structuralOperations.find(
        item => item.op === 'create' && item.collection === 'policy' && item.localId === entry.id,
      );
      return operation?.op === 'create'
        ? {id: operation.localId, name: String(operation.fields['name'] ?? 'New policy')}
        : undefined;
    }
    if (entry.kind === 'address') return this.snapshot.addresses.find(item => item.id === entry.id);
    if (entry.kind === 'address-create') {
      const operation = this.workspaceDraft?.structuralOperations.find(
        item => item.op === 'create' && item.collection === 'address_objects' && item.localId === entry.id,
      );
      return operation?.op === 'create'
        ? {id: operation.localId, name: String(operation.fields['name'] ?? 'New address object')}
        : undefined;
    }
    if (entry.kind === 'port-create' || entry.kind === 'protocol-create') {
      const collection = entry.kind === 'port-create' ? 'port_objects' : 'proto_objects';
      const operation = this.workspaceDraft?.structuralOperations.find(
        item => item.op === 'create' && item.collection === collection && item.localId === entry.id,
      );
      const fallback = entry.kind === 'port-create' ? 'New port object' : 'New protocol object';
      return operation?.op === 'create'
        ? {id: operation.localId, name: String(operation.fields['name'] ?? fallback)}
        : undefined;
    }
    if (entry.kind === 'port') return this.snapshot.ports.find(item => item.id === entry.id);
    if (entry.kind === 'protocol') return this.snapshot.protocols.find(item => item.id === entry.id);
    if (entry.kind === 'settings' && entry.id === 'settings' && this.snapshot.settings) {
      return {id: 'settings', name: 'System settings'};
    }
    if (entry.kind === 'captures' && entry.id === 'captures' && this.snapshot.captures) {
      return {id: 'captures', name: 'Capture settings'};
    }
    if (entry.kind === 'authority') {
      return this.snapshot.securityAssets?.certificateAuthorities.find(item => item.id === entry.id);
    }
    if (entry.kind === 'signature') {
      return this.snapshot.securityAssets?.signatures.find(item => item.id === entry.id);
    }
    if (entry.kind === 'signature-flow') {
      const step = this.snapshot.securityAssets?.signatures.flatMap(item => item.flow)
        .find(item => item.id === entry.id);
      return step ? {id: step.id, name: `Flow ${step.side.toUpperCase()}`} : undefined;
    }
    if (entry.kind === 'content-rule') {
      const rule = this.snapshot.profiles.flatMap(item => item.content?.rules ?? [])
        .find(item => item.id === entry.id);
      return rule ? {id: rule.id, name: 'Content rule'} : undefined;
    }
    return this.snapshot.profiles.find(item => item.id === entry.id);
  }

  private focusActiveDrawer(): void {
    if (this.drawers.length === 0) return;
    const active = this.renderRoot.querySelector<HTMLElement>('.drawer[aria-modal="true"]');
    const target = active?.querySelector<HTMLElement>(
      '.drawer-body input:not([disabled]), .drawer-body select:not([disabled]), ' +
      '.drawer-body textarea:not([disabled]), .drawer-body button:not([disabled])',
    );
    (target ?? active)?.focus();
  }

  private async savePolicyCreate(entry: DrawerEntry): Promise<void> {
    if (!this.structuralDraftsAvailable || !this.draftClient || this.draftCommitting) return;
    const input = (field: string) => this.renderRoot.querySelector<HTMLInputElement>(
      `#policy-create-${field}-${entry.id}`,
    );
    const name = input('name');
    const enabled = input('enabled');
    const sources = input('sources');
    const destinations = input('destinations');
    const action = input('action');
    const protocol = input('protocol');
    const sourcePorts = input('source-ports');
    const destinationPorts = input('destination-ports');
    const features = input('features');
    const nat = input('nat');
    const referenceNames = ['routing', 'tls', 'ssh', 'detection', 'content', 'auth', 'dns', 'script'] as const;
    const references = new Map(referenceNames.map(field => [field, input(field)]));
    const placement = this.renderRoot.querySelector<HTMLSelectElement>(`#policy-create-placement-${entry.id}`);
    if (!name || !enabled || !sources || !destinations || !action || !protocol || !sourcePorts ||
        !destinationPorts || !features || !nat || !placement ||
        [...references.values()].some(value => !value)) return;

    const list = (field: HTMLInputElement) =>
      field.value.split(',').map(value => value.trim()).filter(Boolean);
    const sourceValues = list(sources);
    const destinationValues = list(destinations);
    const sourcePortValues = list(sourcePorts);
    const destinationPortValues = list(destinationPorts);
    const featureValues = list(features);
    const normalizedName = name.value.trim();
    const normalizedAction = action.value.trim();
    const normalizedProtocol = protocol.value.trim();
    const printable = (value: string, maximum: number, empty = false) =>
      (empty || value.length > 0) && value.length <= maximum && !/[\u0000-\u001f\u007f]/u.test(value);
    const validList = (values: ReadonlyArray<string>, empty = true) =>
      (empty || values.length > 0) && values.length <= 256 &&
      values.every(value => printable(value, 128)) && new Set(values).size === values.length;
    const referenceValues = new Map([...references].map(([field, value]) => [field, value!.value.trim()]));
    if (!printable(normalizedName, 128) || !printable(normalizedAction, 32) ||
        !printable(normalizedProtocol, 128) || !validList(sourceValues, false) ||
        !validList(destinationValues, false) ||
        ![sourcePortValues, destinationPortValues, featureValues].every(values => validList(values)) ||
        !printable(nat.value.trim(), 128, true) ||
        [...referenceValues.values()].some(value => !printable(value, 128, true))) {
      this.drawerError = 'Policy fields and unique bounded references are required.';
      return;
    }
    const duplicateLive = this.snapshot?.policies.some((policy, index) =>
      this.presentedValue(`policy.[${index}].name`, policy.name) === normalizedName);
    const duplicateDraft = this.workspaceDraft?.structuralOperations.some(operation =>
      operation.op === 'create' && operation.collection === 'policy' &&
      operation.localId !== entry.id && operation.fields['name'] === normalizedName);
    if (duplicateLive || duplicateDraft) {
      this.drawerError = 'Policy names must be unique.';
      return;
    }

    let position: DraftCreateOperation['position'];
    if (placement.value === 'first' || placement.value === 'last') {
      position = {kind: placement.value, reference: null};
    } else if (placement.value.startsWith('before:')) {
      const reference = placement.value.slice('before:'.length);
      if (!this.snapshot?.policies.some(policy => policy.id === reference)) {
        this.drawerError = 'The selected policy placement is no longer available.';
        return;
      }
      position = {kind: 'before', reference};
    } else {
      this.drawerError = 'A valid policy placement is required.';
      return;
    }
    const fields: DraftCreateOperation['fields'] = {
      name: normalizedName,
      disabled: !enabled.checked,
      proto: normalizedProtocol,
      src: sourceValues,
      sport: sourcePortValues,
      dst: destinationValues,
      dport: destinationPortValues,
      features: featureValues,
      action: normalizedAction,
      nat: nat.value.trim(),
      routing: referenceValues.get('routing')!,
      tls_profile: referenceValues.get('tls')!,
      ssh_profile: referenceValues.get('ssh')!,
      detection_profile: referenceValues.get('detection')!,
      content_profile: referenceValues.get('content')!,
      auth_profile: referenceValues.get('auth')!,
      alg_dns_profile: referenceValues.get('dns')!,
      script_profile: referenceValues.get('script')!,
    };
    const existing = this.pendingPolicyCreate(entry);
    const sameFields = existing !== undefined && Object.keys(existing.fields).length === Object.keys(fields).length &&
      Object.entries(fields).every(([field, value]) =>
        existing.fields[field] !== undefined && this.configValuesEqual(existing.fields[field]!, value));
    if (sameFields && existing!.position.kind === position.kind &&
        existing!.position.reference === position.reference) {
      this.drawerError = undefined;
      this.markDrawerSaved(entry);
      return;
    }

    this.draftSaving = true;
    this.drawerError = undefined;
    this.draftError = undefined;
    const accessEpoch = this.configurationAccessEpoch;
    try {
      const draft = await this.draftClient.upsertOperation(this.draftVersion, {
        op: 'create', localId: entry.id, collection: 'policy', clientId: entry.id,
        parentId: null, position, fields,
      });
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      this.applyDraft(draft);
      this.markDrawerSaved(entry);
      await this.loadDraftPreflight();
    } catch (error) {
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      const message = error instanceof Error ? error.message : 'Policy could not be added to the draft.';
      await this.loadDraft();
      this.drawerError = message;
    } finally {
      if (accessEpoch === this.configurationAccessEpoch) this.draftSaving = false;
    }
  }

  private async saveAddressCreate(entry: DrawerEntry): Promise<void> {
    if (!this.structuralDraftsAvailable || !this.draftClient || this.draftCommitting) return;
    const nameInput = this.renderRoot.querySelector<HTMLInputElement>(`#address-create-name-${entry.id}`);
    const typeInput = this.renderRoot.querySelector<HTMLSelectElement>(`#address-create-type-${entry.id}`);
    const valueInput = this.renderRoot.querySelector<HTMLInputElement>(`#address-create-value-${entry.id}`);
    const name = nameInput?.value.trim() ?? '';
    const type = typeInput?.value ?? '';
    const value = valueInput?.value.trim() ?? '';
    const addressTypes = new Set(['cidr', 'fqdn', 'host', 'subnet', 'range']);
    if (name.length === 0 || name.length > 128 || value.length === 0 || value.length > 1024 ||
        !addressTypes.has(type)) {
      this.drawerError = 'Name, type, and address are required and must fit the configuration limits.';
      return;
    }
    const duplicateLive = this.snapshot?.addresses.some(address =>
      address.name === name || this.addressDisplayName(address) === name);
    const duplicateDraft = this.workspaceDraft?.structuralOperations.some(operation =>
      operation.op === 'create' && operation.collection === 'address_objects' &&
      operation.localId !== entry.id && operation.fields['name'] === name);
    if (duplicateLive || duplicateDraft) {
      this.drawerError = 'An address object with this name already exists.';
      return;
    }
    const existing = this.pendingAddressCreate(entry);
    if (existing?.fields['name'] === name && existing.fields['type'] === type &&
        existing.fields['value'] === value) {
      this.drawerError = undefined;
      this.markDrawerSaved(entry);
      return;
    }
    this.draftSaving = true;
    this.drawerError = undefined;
    this.draftError = undefined;
    const accessEpoch = this.configurationAccessEpoch;
    try {
      const draft = await this.draftClient.upsertOperation(this.draftVersion, {
        op: 'create',
        localId: entry.id,
        collection: 'address_objects',
        clientId: entry.id,
        parentId: null,
        position: {kind: 'last', reference: null},
        fields: {name, type, value},
      });
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      this.applyDraft(draft);
      this.markDrawerSaved(entry);
      await this.loadDraftPreflight();
    } catch (error) {
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      const message = error instanceof Error ? error.message : 'Address object could not be added to the draft.';
      await this.loadDraft();
      this.drawerError = message;
    } finally {
      if (accessEpoch === this.configurationAccessEpoch) this.draftSaving = false;
    }
  }

  private pendingSimpleObjectCreate(entry: DrawerEntry): DraftCreateOperation | undefined {
    const collection = entry.kind === 'port-create' ? 'port_objects'
      : entry.kind === 'protocol-create' ? 'proto_objects' : undefined;
    if (!collection) return undefined;
    const operation = this.workspaceDraft?.structuralOperations.find(
      item => item.op === 'create' && item.collection === collection && item.localId === entry.id,
    );
    return operation?.op === 'create' ? operation : undefined;
  }

  private async saveSimpleObjectCreate(entry: DrawerEntry): Promise<void> {
    if (!this.structuralDraftsAvailable || !this.draftClient || this.draftCommitting ||
        (entry.kind !== 'port-create' && entry.kind !== 'protocol-create')) return;
    const port = entry.kind === 'port-create';
    const prefix = port ? 'port-create' : 'protocol-create';
    const nameInput = this.renderRoot.querySelector<HTMLInputElement>(`#${prefix}-name-${entry.id}`);
    const firstInput = this.renderRoot.querySelector<HTMLInputElement>(
      `#${prefix}-${port ? 'start' : 'number'}-${entry.id}`,
    );
    const endInput = port
      ? this.renderRoot.querySelector<HTMLInputElement>(`#port-create-end-${entry.id}`)
      : undefined;
    if (!nameInput || !firstInput || (port && !endInput)) return;
    const name = nameInput.value.trim();
    const first = firstInput.valueAsNumber;
    const end = endInput?.valueAsNumber;
    const maximum = port ? 65535 : 255;
    if (name.length === 0 || name.length > 128 || /[\u0000-\u001f\u007f]/u.test(name) ||
        !Number.isInteger(first) || first < 0 || first > maximum ||
        (port && (!Number.isInteger(end) || end! < first || end! > maximum))) {
      this.drawerError = port
        ? 'A unique name and a valid ascending port range from 0 to 65535 are required.'
        : 'A unique name and a protocol number from 0 to 255 are required.';
      return;
    }
    const collection = port ? 'port_objects' : 'proto_objects';
    const duplicateLiveName = port
      ? this.snapshot?.ports.some((item, index) =>
        this.presentedValue(`port_objects.[${index}].name`, item.name) === name)
      : this.snapshot?.protocols.some((item, index) =>
        this.presentedValue(`proto_objects.[${index}].name`, item.name) === name);
    const duplicateDraftName = this.workspaceDraft?.structuralOperations.some(operation =>
      operation.op === 'create' && operation.collection === collection &&
      operation.localId !== entry.id && operation.fields['name'] === name);
    const duplicateProtocolNumber = !port && (
      this.snapshot?.protocols.some((item, index) =>
        this.presentedValue(`proto_objects.[${index}].id`, item.number) === first) ||
      this.workspaceDraft?.structuralOperations.some(operation =>
        operation.op === 'create' && operation.collection === 'proto_objects' &&
        operation.localId !== entry.id && operation.fields['id'] === first)
    );
    if (duplicateLiveName || duplicateDraftName || duplicateProtocolNumber) {
      this.drawerError = port
        ? 'Port object names must be unique.'
        : 'Protocol object names and numbers must be unique.';
      return;
    }
    const fields: DraftCreateOperation['fields'] = port
      ? {name, start: first, end: end!}
      : {name, id: first};
    const existing = this.pendingSimpleObjectCreate(entry);
    const unchanged = existing !== undefined && Object.keys(existing.fields).length === Object.keys(fields).length &&
      Object.entries(fields).every(([field, value]) => Object.is(existing.fields[field], value));
    if (unchanged) {
      this.drawerError = undefined;
      this.markDrawerSaved(entry);
      return;
    }

    this.draftSaving = true;
    this.drawerError = undefined;
    this.draftError = undefined;
    const accessEpoch = this.configurationAccessEpoch;
    try {
      const draft = await this.draftClient.upsertOperation(this.draftVersion, {
        op: 'create', localId: entry.id, collection, clientId: entry.id,
        parentId: null, position: {kind: 'last', reference: null}, fields,
      });
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      this.applyDraft(draft);
      this.markDrawerSaved(entry);
      await this.loadDraftPreflight();
    } catch (error) {
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      const fallback = port ? 'Port object could not be added to the draft.'
        : 'Protocol object could not be added to the draft.';
      const message = error instanceof Error ? error.message : fallback;
      await this.loadDraft();
      this.drawerError = message;
    } finally {
      if (accessEpoch === this.configurationAccessEpoch) this.draftSaving = false;
    }
  }

  private async saveToDraft(entry: DrawerEntry): Promise<void> {
    if (entry.kind === 'policy-create') {
      await this.savePolicyCreate(entry);
      return;
    }
    if (entry.kind === 'address-create') {
      await this.saveAddressCreate(entry);
      return;
    }
    if (entry.kind === 'port-create' || entry.kind === 'protocol-create') {
      await this.saveSimpleObjectCreate(entry);
      return;
    }
    if (this.snapshot?.source !== 'live') {
      this.draftObjects = new Set(this.draftObjects).add(`${entry.kind}:${entry.id}`);
      this.draftChangeCount = this.draftObjects.size;
      this.markDrawerSaved(entry);
      return;
    }
    if (!this.draftAvailable || !this.draftClient || this.draftCommitting) return;
    const proposedChanges = this.draftChanges(entry);
    if (!proposedChanges) return;
    const changes = this.writableDraftChanges(proposedChanges);
    if (!changes) return;
    const initial = this.drawerInitialChanges.get(this.drawerKey(entry));
    const edited = initial
      ? changes.filter(change => {
        const initialValue = initial.get(change.path);
        return initialValue === undefined || !this.draftScalarsEqual(initialValue, change.value);
      })
      : changes;
    if (edited.length === 0) {
      this.markDrawerSaved(entry);
      return;
    }
    const pendingPaths = new Set((this.workspaceDraft?.changes ?? []).map(change => change.path));
    const persistentValues = this.snapshot ? persistentConfigurationValues(this.snapshot) : undefined;
    const removePaths: string[] = [];
    const upserts: DraftChange[] = [];
    for (const change of edited) {
      const persistent = this.valueOrigin(change.path)?.persistentValue ?? persistentValues?.get(change.path);
      if (pendingPaths.has(change.path) && persistent !== undefined &&
          this.configValuesEqual(persistent, change.value)) {
        removePaths.push(change.path);
      } else {
        upserts.push(change);
      }
    }
    this.draftSaving = true;
    const accessEpoch = this.configurationAccessEpoch;
    this.draftError = undefined;
    try {
      const draft = removePaths.length > 0
        ? await this.draftClient.reconcile(this.draftVersion, upserts, removePaths)
        : await this.draftClient.upsertMany(this.draftVersion, upserts);
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      this.applyDraft(draft);
      await this.loadDraftPreflight();
      this.markDrawerSaved(entry);
      if (entry.kind === 'settings' || entry.kind === 'captures' || entry.kind === 'profile' ||
          entry.kind === 'authority' || entry.kind === 'signature-flow' || entry.kind === 'content-rule') {
        this.renderRoot.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(
          '[id*="-write-"][id$="-value"], #settings-api-keys-value',
        ).forEach(input => { input.value = ''; });
        this.renderRoot.querySelectorAll<HTMLSelectElement>(
          '[id*="-write-"][id$="-mode"], #settings-api-keys-mode',
        ).forEach(select => { select.value = 'unchanged'; });
      }
      await this.updateComplete;
      this.captureDrawerInitialChanges(entry);
    } catch (error) {
      if (!this.draftAccessIsCurrent(accessEpoch)) return;
      const message = error instanceof Error ? error.message : 'Draft change could not be saved.';
      await this.loadDraft();
      this.draftError = message;
    } finally {
      if (accessEpoch === this.configurationAccessEpoch) this.draftSaving = false;
    }
  }

  private valueOrigin(path: string) {
    return this.snapshot?.valueOrigins.find(item => item.path === path);
  }

  private pendingDraftValue(path: string): DraftScalar | undefined {
    if (this.valueOrigin(path)?.editable === false) return undefined;
    const value = this.workspaceDraft?.changes.find(change => change.path === path)?.value;
    if (typeof value === 'string' && /^\[redacted:(?:clear|replace(?::\d+)?)\]$/u.test(value)) {
      return undefined;
    }
    return value;
  }

  private presentedValue<T extends ConfigScalar>(path: string, liveValue: T): T {
    const pending = this.pendingDraftValue(path);
    return pending !== undefined && !Array.isArray(pending) && typeof pending === typeof liveValue
      ? pending as T
      : liveValue;
  }

  private presentedListValue<T extends string | number>(
    path: string, liveValue: ReadonlyArray<T>, itemType: 'string' | 'number',
  ): ReadonlyArray<T> {
    const pending = this.pendingDraftValue(path);
    return Array.isArray(pending) && pending.every(item => typeof item === itemType)
      ? pending as ReadonlyArray<T>
      : liveValue;
  }

  private persistentValue<T extends ConfigScalar>(path: string, fallback: T): T {
    const pending = this.pendingDraftValue(path);
    if (pending !== undefined && !Array.isArray(pending) && typeof pending === typeof fallback) {
      return pending as T;
    }
    const value = this.valueOrigin(path)?.persistentValue;
    return value !== undefined && typeof value === typeof fallback ? value as T : fallback;
  }

  private persistentListValue<T extends string | number>(
    path: string, fallback: ReadonlyArray<T>, itemType: 'string' | 'number',
  ): ReadonlyArray<T> {
    const pending = this.pendingDraftValue(path);
    if (Array.isArray(pending) && pending.every(item => typeof item === itemType)) {
      return pending as ReadonlyArray<T>;
    }
    const value = this.valueOrigin(path)?.persistentValue;
    return Array.isArray(value) && value.every(item => typeof item === itemType)
      ? value as ReadonlyArray<T>
      : fallback;
  }

  private configValuesEqual(left: ConfigValue, right: DraftScalar): boolean {
    if (!Array.isArray(left) || !Array.isArray(right)) return Object.is(left, right);
    return left.length === right.length && left.every((item, index) => Object.is(item, right[index]));
  }

  private formatConfigValue(value: ConfigValue): string {
    if (!Array.isArray(value)) return String(value);
    if (value.length === 0) return 'Empty list';
    const preview = value.slice(0, 4).join(', ');
    return value.length > 4 ? `${preview}, … · ${value.length} items` : preview;
  }

  private originReadOnly(path: string, otherwiseReadOnly: boolean): boolean {
    return otherwiseReadOnly || this.valueOrigin(path)?.editable === false;
  }

  private writableDraftChanges(changes: ReadonlyArray<DraftChange>): ReadonlyArray<DraftChange> | undefined {
    const changedLockedValue = changes.find(change => {
      const origin = this.valueOrigin(change.path);
      return origin?.editable === false &&
        !this.configValuesEqual(origin.persistentValue, change.value) &&
        !this.configValuesEqual(origin.effectiveValue, change.value);
    });
    if (changedLockedValue) {
      this.draftError = `${changedLockedValue.path} is owned by an active augment layer and cannot be changed here.`;
      return undefined;
    }
    return changes.filter(change => this.valueOrigin(change.path)?.editable !== false);
  }

  private renamedReferenceChanges(
    kind: 'address' | 'port' | 'protocol' | 'profile',
    entityId: string,
    currentName: string,
    nextName: string,
  ): ReadonlyArray<DraftChange> {
    if (!this.snapshot || currentName === nextName) return [];
    const changes = new Map<string, DraftChange>();
    const replaceList = (path: string, current: ReadonlyArray<string>) => {
      const presented = this.presentedListValue(path, current, 'string');
      if (!presented.includes(currentName)) return;
      changes.set(path, {
        path,
        value: presented.map(value => value === currentName ? nextName : value),
      });
    };
    const replaceScalar = (path: string, current: string) => {
      const presented = this.presentedValue(path, current);
      if (presented === currentName) changes.set(path, {path, value: nextName});
    };

    for (const [index, policy] of this.snapshot.policies.entries()) {
      const base = `policy.[${index}]`;
      if (kind === 'address') {
        replaceList(`${base}.src`, policy.sources.map(item => item.name));
        replaceList(`${base}.dst`, policy.destinations.map(item => item.name));
      } else if (kind === 'port') {
        replaceList(`${base}.sport`, policy.sourcePorts);
        replaceList(`${base}.dport`, policy.destinationPorts);
      } else if (kind === 'protocol') {
        replaceScalar(`${base}.proto`, policy.protocol);
      } else {
        const profile = this.snapshot.profiles.find(item => item.id === entityId);
        if (!profile) continue;
        if (profile.routing) replaceScalar(`${base}.routing`, policy.routing);
        else if (profile.tls) replaceScalar(`${base}.tls_profile`, policy.tlsProfile);
        else if (profile.ssh) replaceScalar(`${base}.ssh_profile`, policy.sshProfile);
        else if (profile.detection) replaceScalar(`${base}.detection_profile`, policy.detectionProfile);
        else if (profile.content) replaceScalar(`${base}.content_profile`, policy.contentProfile);
        else if (profile.authentication) replaceScalar(`${base}.auth_profile`, policy.authProfile);
        else if (profile.dns) replaceScalar(`${base}.alg_dns_profile`, policy.dnsProfile);
        else if (profile.script) replaceScalar(`${base}.script_profile`, policy.scriptProfile);
      }
    }

    if (kind === 'address' || kind === 'port') {
      const routingProfiles = this.snapshot.profiles.filter(item => item.routing !== null);
      for (const [index, profile] of routingProfiles.entries()) {
        const base = `routing.[${index}]`;
        if (kind === 'address') {
          replaceList(`${base}.dnat_address`, profile.routing!.destinationAddresses);
        } else {
          replaceList(`${base}.dnat_port`, profile.routing!.destinationPorts);
        }
      }
    }
    return [...changes.values()];
  }

  private duplicateConfigurationName(
    kind: 'policy' | 'address' | 'port' | 'protocol' | 'profile',
    entityId: string,
    nextName: string,
  ): boolean {
    if (!this.snapshot) return false;
    if (kind === 'policy') {
      return this.snapshot.policies.some((item, index) => item.id !== entityId &&
        this.presentedValue(`policy.[${index}].name`, item.name) === nextName);
    }
    if (kind === 'address') {
      return this.snapshot.addresses.some((item, index) => item.id !== entityId &&
        this.presentedValue(`address_objects.[${index}].name`, item.name) === nextName);
    }
    if (kind === 'port') {
      return this.snapshot.ports.some((item, index) => item.id !== entityId &&
        this.presentedValue(`port_objects.[${index}].name`, item.name) === nextName);
    }
    if (kind === 'protocol') {
      return this.snapshot.protocols.some((item, index) => item.id !== entityId &&
        this.presentedValue(`proto_objects.[${index}].name`, item.name) === nextName);
    }
    const current = this.snapshot.profiles.find(item => item.id === entityId);
    const prefix = this.profileOriginPrefixes().get(entityId);
    if (!current || !prefix) return false;
    const sameCollection = (item: ProfileObject) =>
      Boolean(item.routing) === Boolean(current.routing) && Boolean(item.tls) === Boolean(current.tls) &&
      Boolean(item.detection) === Boolean(current.detection) && Boolean(item.content) === Boolean(current.content) &&
      Boolean(item.ssh) === Boolean(current.ssh) && Boolean(item.dns) === Boolean(current.dns) &&
      Boolean(item.script) === Boolean(current.script) &&
      Boolean(item.authentication) === Boolean(current.authentication);
    const prefixes = this.profileOriginPrefixes();
    return this.snapshot.profiles.some(item => {
      const itemPrefix = prefixes.get(item.id);
      return item.id !== entityId && itemPrefix !== undefined && sameCollection(item) &&
        this.presentedValue(`${itemPrefix}name`, item.name) === nextName;
    });
  }

  private draftChanges(entry: DrawerEntry): ReadonlyArray<DraftChange> | undefined {
    if (!this.snapshot) return undefined;
    if (entry.kind === 'settings') return this.systemSettingsDraftChanges();
    if (entry.kind === 'captures') return this.captureSettingsDraftChanges();
    if (entry.kind === 'content-rule') {
      const profile = this.snapshot.profiles.find(item => item.content?.rules.some(rule => rule.id === entry.id));
      const contentProfiles = this.snapshot.profiles.filter(item => item.content !== null);
      const profileIndex = profile ? contentProfiles.findIndex(item => item.id === profile.id) : -1;
      const ruleIndex = profile?.content?.rules.findIndex(rule => rule.id === entry.id) ?? -1;
      const matchMode = this.renderRoot.querySelector<HTMLSelectElement>(
        `#content-rule-write-match-${entry.id}-mode`,
      );
      const match = this.renderRoot.querySelector<HTMLTextAreaElement>(
        `#content-rule-write-match-${entry.id}-value`,
      );
      const replacementMode = this.renderRoot.querySelector<HTMLSelectElement>(
        `#content-rule-write-replacement-${entry.id}-mode`,
      );
      const replacement = this.renderRoot.querySelector<HTMLTextAreaElement>(
        `#content-rule-write-replacement-${entry.id}-value`,
      );
      const fillLength = this.renderRoot.querySelector<HTMLSelectElement>(
        `#content-rule-fill-length-${entry.id}`,
      );
      const replaceEachNth = this.renderRoot.querySelector<HTMLInputElement>(
        `#content-rule-replace-each-${entry.id}`,
      );
      if (profileIndex < 0 || ruleIndex < 0 || !matchMode || !match || !replacementMode || !replacement ||
          !fillLength || !replaceEachNth || !['true', 'false'].includes(fillLength.value) ||
          !['unchanged', 'replace'].includes(matchMode.value) ||
          !['unchanged', 'replace', 'clear'].includes(replacementMode.value)) return undefined;
      const replaceEachValue = replaceEachNth.valueAsNumber;
      if (!Number.isInteger(replaceEachValue) || replaceEachValue < -2147483648 ||
          replaceEachValue > 2147483647) {
        this.draftError = 'The replacement interval must be a signed 32-bit integer.';
        return undefined;
      }
      const validExpression = (value: string) =>
        value.length > 0 && value.length <= 65536 && !value.includes('\0');
      if ((matchMode.value === 'replace' && !validExpression(match.value)) ||
          (replacementMode.value === 'replace' && !validExpression(replacement.value))) {
        this.draftError = 'Content rule replacements must contain 1 to 65536 characters.';
        return undefined;
      }
      const base = `content_profiles.[${profileIndex}].content_rules.[${ruleIndex}]`;
      return [
        {path: `${base}.fill_length`, value: fillLength.value === 'true'},
        {path: `${base}.replace_each_nth`, value: replaceEachValue},
        ...(matchMode.value === 'replace' ? [{path: `${base}.match`, value: match.value}] : []),
        ...(replacementMode.value === 'replace'
          ? [{path: `${base}.replace`, value: replacement.value}]
          : replacementMode.value === 'clear'
            ? [{path: `${base}.replace`, value: ''}]
            : []),
      ];
    }
    if (entry.kind === 'signature') {
      const signature = this.snapshot.securityAssets?.signatures.find(item => item.id === entry.id);
      if (!signature) return undefined;
      const index = this.snapshot.securityAssets!.signatures
        .filter(item => item.kind === signature.kind).findIndex(item => item.id === signature.id);
      const input = (field: string) => this.renderRoot.querySelector<HTMLInputElement>(
        `#signature-${field}-${entry.id}`,
      );
      const category = input('category');
      const name = input('name');
      const side = this.renderRoot.querySelector<HTMLSelectElement>(`#signature-side-${entry.id}`);
      const severity = input('severity');
      const group = input('group');
      const enables = input('enables');
      const engine = input('engine');
      if (index < 0 || !category || !name || !side || !severity || !group || !enables || !engine ||
          !['client', 'server'].includes(side.value)) return undefined;
      const severityValue = severity.valueAsNumber;
      const values: [string, string, string, string, string] = [
        category.value.trim(), name.value.trim(), group.value.trim(),
        enables.value.trim(), engine.value.trim(),
      ];
      if (!Number.isInteger(severityValue) || severityValue < -2147483648 || severityValue > 2147483647 ||
          values[1].length === 0 || values.some(value => value.length > 128 ||
          /[\u0000-\u001f\u007f]/u.test(value))) {
        this.draftError = 'Signature metadata must use bounded printable values and include a name.';
        return undefined;
      }
      const base = `${signature.kind}_signatures.[${index}]`;
      return [
        {path: `${base}.cat`, value: values[0]},
        {path: `${base}.name`, value: values[1]},
        {path: `${base}.side`, value: side.value},
        {path: `${base}.severity`, value: severityValue},
        {path: `${base}.group`, value: values[2]},
        {path: `${base}.enables`, value: values[3]},
        {path: `${base}.engine`, value: values[4]},
      ];
    }
    if (entry.kind === 'signature-flow') {
      const signature = this.snapshot.securityAssets?.signatures
        .find(item => item.flow.some(step => step.id === entry.id));
      const step = signature?.flow.find(item => item.id === entry.id);
      if (!signature || !step) return undefined;
      const signatureIndex = this.snapshot.securityAssets!.signatures
        .filter(item => item.kind === signature.kind).findIndex(item => item.id === signature.id);
      const flowIndex = signature.flow.findIndex(item => item.id === step.id);
      const side = this.renderRoot.querySelector<HTMLSelectElement>(`#signature-flow-side-${entry.id}`);
      const type = this.renderRoot.querySelector<HTMLSelectElement>(`#signature-flow-type-${entry.id}`);
      const start = this.renderRoot.querySelector<HTMLInputElement>(`#signature-flow-start-${entry.id}`);
      const maximum = this.renderRoot.querySelector<HTMLInputElement>(`#signature-flow-maximum-${entry.id}`);
      const mode = this.renderRoot.querySelector<HTMLSelectElement>(
        `#signature-flow-write-expression-${entry.id}-mode`,
      );
      const expression = this.renderRoot.querySelector<HTMLTextAreaElement>(
        `#signature-flow-write-expression-${entry.id}-value`,
      );
      if (signatureIndex < 0 || flowIndex < 0 || !side || !type || !start || !maximum || !mode ||
          !expression || !['r', 'w'].includes(side.value) || !['regex', 'simple'].includes(type.value) ||
          !['unchanged', 'replace'].includes(mode.value)) return undefined;
      const bytesStart = start.valueAsNumber;
      const bytesMax = maximum.valueAsNumber;
      if (![bytesStart, bytesMax].every(value => Number.isSafeInteger(value) && value >= 0)) {
        this.draftError = 'Signature byte positions must be non-negative safe integers.';
        return undefined;
      }
      if (mode.value === 'replace' &&
          (expression.value.length === 0 || expression.value.length > 65536 || expression.value.includes('\0'))) {
        this.draftError = 'A replacement expression from 1 to 65536 characters is required.';
        return undefined;
      }
      const base = `${signature.kind}_signatures.[${signatureIndex}].flow.[${flowIndex}]`;
      return [
        {path: `${base}.side`, value: side.value},
        {path: `${base}.type`, value: type.value},
        {path: `${base}.bytes_start`, value: bytesStart},
        {path: `${base}.bytes_max`, value: bytesMax},
        ...(mode.value === 'replace'
          ? [{path: `${base}.signature`, value: expression.value}]
          : []),
      ];
    }
    if (entry.kind === 'authority') {
      const authorities = this.snapshot.securityAssets?.certificateAuthorities ?? [];
      const index = authorities.findIndex(item => item.id === entry.id);
      const name = this.renderRoot.querySelector<HTMLInputElement>(`#authority-name-${entry.id}`);
      const mode = this.renderRoot.querySelector<HTMLSelectElement>(`#authority-write-path-${entry.id}-mode`);
      const input = this.renderRoot.querySelector<HTMLInputElement>(`#authority-write-path-${entry.id}-value`);
      if (index < 0 || !name || !mode || !input ||
          !['unchanged', 'replace', 'clear'].includes(mode.value)) return undefined;
      const normalizedName = name.value.trim();
      if (normalizedName.length === 0 || normalizedName.length > 128 ||
          /[\u0000-\u001f\u007f]/u.test(normalizedName)) {
        this.draftError = 'A certificate authority name up to 128 characters is required.';
        return undefined;
      }
      const replacement = input.value;
      if (mode.value === 'replace' &&
          (replacement.length === 0 || replacement.length > 1024 || !replacement.startsWith('/') ||
           /[\u0000-\u001f\u007f]/u.test(replacement))) {
        this.draftError = 'An absolute replacement CA path up to 1024 characters is required.';
        return undefined;
      }
      return [
        {path: `tls_ca.[${index}].name`, value: normalizedName},
        ...(mode.value === 'replace'
          ? [{path: `tls_ca.[${index}].path`, value: replacement}]
          : mode.value === 'clear'
            ? [{path: `tls_ca.[${index}].path`, value: ''}]
            : []),
      ];
    }
    if (entry.kind === 'policy') {
      const index = this.snapshot.policies.findIndex(item => item.id === entry.id);
      const name = this.renderRoot.querySelector<HTMLInputElement>(`#policy-name-${entry.id}`);
      const enabled = this.renderRoot.querySelector<HTMLInputElement>(`#policy-enabled-${entry.id}`);
      const destination = this.renderRoot.querySelector<HTMLInputElement>(`#destination-${entry.id}`);
      const action = this.renderRoot.querySelector<HTMLInputElement>(`#action-${entry.id}`);
      const field = (id: string) => this.renderRoot.querySelector<HTMLInputElement>(`#policy-${id}-${entry.id}`);
      const protocol = field('protocol');
      const sources = field('sources');
      const sourcePorts = field('source-ports');
      const destinationPorts = field('destination-ports');
      const features = field('features');
      const nat = field('nat');
      const referenceIds = ['routing', 'tls', 'ssh', 'detection', 'content', 'auth', 'dns', 'script'] as const;
      const references = new Map(referenceIds.map(id => [id, field(id)]));
      if (index < 0 || !name || !enabled || !destination || !action || !protocol || !sources ||
          !sourcePorts || !destinationPorts || !features || !nat ||
          [...references.values()].some(value => !value)) return undefined;
      const list = (input: HTMLInputElement) => input.value.split(',').map(value => value.trim()).filter(Boolean);
      const sourceValues = list(sources);
      const sourcePortValues = list(sourcePorts);
      const destinations = list(destination);
      const destinationPortValues = list(destinationPorts);
      const featureValues = list(features);
      const normalizedName = name.value.trim();
      const validList = (values: ReadonlyArray<string>) => values.length <= 256 &&
        values.every(value => value.length <= 128) && new Set(values).size === values.length;
      if (normalizedName.length === 0 || normalizedName.length > 128 ||
          action.value.trim().length === 0 || action.value.trim().length > 32 ||
          protocol.value.trim().length === 0 || protocol.value.trim().length > 128 ||
          sourceValues.length === 0 || destinations.length === 0 ||
          ![sourceValues, sourcePortValues, destinations, destinationPortValues, featureValues].every(validList) ||
          [nat, ...references.values()].some(value => value!.value.trim().length > 128)) {
        this.draftError = 'Policy fields and unique bounded references are required.';
        return undefined;
      }
      if (this.duplicateConfigurationName('policy', entry.id, normalizedName)) {
        this.draftError = 'Policy names must be unique.';
        return undefined;
      }
      return [
        {path: `policy.[${index}].name`, value: normalizedName},
        {path: `policy.[${index}].disabled`, value: !enabled.checked},
        {path: `policy.[${index}].proto`, value: protocol.value.trim()},
        {path: `policy.[${index}].src`, value: sourceValues},
        {path: `policy.[${index}].sport`, value: sourcePortValues},
        {path: `policy.[${index}].dst`, value: destinations},
        {path: `policy.[${index}].dport`, value: destinationPortValues},
        {path: `policy.[${index}].features`, value: featureValues},
        {path: `policy.[${index}].action`, value: action.value.trim()},
        {path: `policy.[${index}].nat`, value: nat.value.trim()},
        {path: `policy.[${index}].routing`, value: references.get('routing')!.value.trim()},
        {path: `policy.[${index}].tls_profile`, value: references.get('tls')!.value.trim()},
        {path: `policy.[${index}].ssh_profile`, value: references.get('ssh')!.value.trim()},
        {path: `policy.[${index}].detection_profile`, value: references.get('detection')!.value.trim()},
        {path: `policy.[${index}].content_profile`, value: references.get('content')!.value.trim()},
        {path: `policy.[${index}].auth_profile`, value: references.get('auth')!.value.trim()},
        {path: `policy.[${index}].alg_dns_profile`, value: references.get('dns')!.value.trim()},
        {path: `policy.[${index}].script_profile`, value: references.get('script')!.value.trim()},
      ];
    }
    if (entry.kind === 'address') {
      const index = this.snapshot.addresses.findIndex(item => item.id === entry.id);
      const name = this.renderRoot.querySelector<HTMLInputElement>(`#address-name-${entry.id}`);
      const type = this.renderRoot.querySelector<HTMLSelectElement>(`#address-type-${entry.id}`);
      const value = this.renderRoot.querySelector<HTMLInputElement>(`#address-value-${entry.id}`);
      if (index < 0 || !name || !type || !value) return undefined;
      const normalizedName = name.value.trim();
      const currentName = this.persistentValue(`address_objects.[${index}].name`, this.snapshot.addresses[index]!.name);
      if (normalizedName.length === 0 || normalizedName.length > 128 || value.value.trim().length === 0 ||
          !['cidr', 'fqdn', 'host', 'subnet', 'range'].includes(type.value)) {
        this.draftError = 'Name and address value are required.';
        return undefined;
      }
      if (this.duplicateConfigurationName('address', entry.id, normalizedName)) {
        this.draftError = 'Address object names must be unique.';
        return undefined;
      }
      return [
        {path: `address_objects.[${index}].name`, value: normalizedName},
        {path: `address_objects.[${index}].type`, value: type.value},
        {path: `address_objects.[${index}].value`, value: value.value.trim()},
        ...this.renamedReferenceChanges('address', entry.id, currentName, normalizedName),
      ];
    }
    if (entry.kind === 'port') {
      const index = this.snapshot.ports.findIndex(item => item.id === entry.id);
      const name = this.renderRoot.querySelector<HTMLInputElement>(`#port-name-${entry.id}`);
      const start = this.renderRoot.querySelector<HTMLInputElement>(`#port-start-${entry.id}`);
      const end = this.renderRoot.querySelector<HTMLInputElement>(`#port-end-${entry.id}`);
      const startValue = start?.valueAsNumber ?? Number.NaN;
      const endValue = end?.valueAsNumber ?? Number.NaN;
      if (index < 0 || !name || !start || !end) return undefined;
      const normalizedName = name.value.trim();
      const currentName = this.persistentValue(`port_objects.[${index}].name`, this.snapshot.ports[index]!.name);
      if (normalizedName.length === 0 || normalizedName.length > 128 ||
          !Number.isInteger(startValue) || !Number.isInteger(endValue) ||
          startValue < 0 || endValue > 65535 || startValue > endValue) {
        this.draftError = 'Name and a valid port range from 0 to 65535 are required.';
        return undefined;
      }
      if (this.duplicateConfigurationName('port', entry.id, normalizedName)) {
        this.draftError = 'Port object names must be unique.';
        return undefined;
      }
      return [
        {path: `port_objects.[${index}].name`, value: normalizedName},
        {path: `port_objects.[${index}].start`, value: startValue},
        {path: `port_objects.[${index}].end`, value: endValue},
        ...this.renamedReferenceChanges('port', entry.id, currentName, normalizedName),
      ];
    }
    if (entry.kind === 'protocol') {
      const index = this.snapshot.protocols.findIndex(item => item.id === entry.id);
      const name = this.renderRoot.querySelector<HTMLInputElement>(`#protocol-name-${entry.id}`);
      const number = this.renderRoot.querySelector<HTMLInputElement>(`#protocol-number-${entry.id}`);
      const numberValue = number?.valueAsNumber ?? Number.NaN;
      if (index < 0 || !name || !number) return undefined;
      const normalizedName = name.value.trim();
      const currentName = this.persistentValue(`proto_objects.[${index}].name`, this.snapshot.protocols[index]!.name);
      if (normalizedName.length === 0 || normalizedName.length > 128 || !Number.isInteger(numberValue) ||
          numberValue < 0 || numberValue > 255) {
        this.draftError = 'Name and a valid IP protocol number from 0 to 255 are required.';
        return undefined;
      }
      if (this.duplicateConfigurationName('protocol', entry.id, normalizedName)) {
        this.draftError = 'Protocol object names must be unique.';
        return undefined;
      }
      return [
        {path: `proto_objects.[${index}].name`, value: normalizedName},
        {path: `proto_objects.[${index}].id`, value: numberValue},
        ...this.renamedReferenceChanges('protocol', entry.id, currentName, normalizedName),
      ];
    }
    if (entry.kind === 'profile') {
      const profile = this.snapshot.profiles.find(item => item.id === entry.id);
      const name = this.renderRoot.querySelector<HTMLInputElement>(`#profile-name-${entry.id}`);
      if (!profile || !name || name.value.trim().length === 0 || name.value.trim().length > 128) {
        this.draftError = 'A profile name up to 128 characters is required.';
        return undefined;
      }
      const prefix = this.profileOriginPrefixes().get(entry.id);
      if (!prefix) return undefined;
      const normalizedName = name.value.trim();
      const currentName = this.persistentValue(`${prefix}name`, profile.name);
      if (this.duplicateConfigurationName('profile', entry.id, normalizedName)) {
        this.draftError = 'Profile names must be unique within their configuration section.';
        return undefined;
      }
      const renameChanges = this.renamedReferenceChanges(
        'profile', entry.id, currentName, normalizedName,
      );
      if (profile.routing) {
        const profiles = this.snapshot.profiles.filter(item => item.routing !== null);
        const index = profiles.findIndex(item => item.id === entry.id);
        const addresses = this.renderRoot.querySelector<HTMLInputElement>(`#routing-addresses-${entry.id}`);
        const ports = this.renderRoot.querySelector<HTMLInputElement>(`#routing-ports-${entry.id}`);
        const loadBalancing = this.renderRoot.querySelector<HTMLSelectElement>(`#routing-load-balancing-${entry.id}`);
        const rewriteSni = this.renderRoot.querySelector<HTMLInputElement>(`#routing-rewrite-sni-${entry.id}`);
        const rewriteSniTo = this.renderRoot.querySelector<HTMLInputElement>(`#routing-rewrite-sni-to-${entry.id}`);
        if (index < 0 || !addresses || !ports || !loadBalancing || !rewriteSni || !rewriteSniTo) return undefined;
        const addressValues = addresses.value.split(',').map(value => value.trim()).filter(Boolean);
        const portValues = ports.value.split(',').map(value => value.trim()).filter(Boolean);
        const sourceSni = rewriteSni.value.trim();
        const targetSni = rewriteSniTo.value.trim();
        const validReferences = (values: ReadonlyArray<string>) =>
          values.length <= 256 && values.every(value => value.length <= 128) &&
          new Set(values).size === values.length;
        if (!validReferences(addressValues) || !validReferences(portValues) ||
            !['round-robin', 'sticky-l3', 'sticky-l4'].includes(loadBalancing.value) ||
            sourceSni.length > 1024 || targetSni.length > 1024 ||
            (sourceSni.length === 0) !== (targetSni.length === 0)) {
          this.draftError = 'Routing references must be unique and SNI rewrite requires both values.';
          return undefined;
        }
        return [
          {path: `routing.[${index}].name`, value: normalizedName},
          ...renameChanges,
          {path: `routing.[${index}].dnat_address`, value: addressValues},
          {path: `routing.[${index}].dnat_port`, value: portValues},
          {path: `routing.[${index}].dnat_lb_method`, value: loadBalancing.value},
          {path: `routing.[${index}].rewrite_sni`, value: sourceSni},
          {path: `routing.[${index}].rewrite_sni_to`, value: targetSni},
        ];
      }
      if (profile.tls) {
        const profiles = this.snapshot.profiles.filter(item => item.tls !== null);
        const index = profiles.findIndex(item => item.id === entry.id);
        if (index < 0) return undefined;
        const booleanFields = [
          ['inspect', 'inspect'],
          ['use_pfs', 'use-pfs'],
          ['left_use_pfs', 'left-use-pfs'],
          ['right_use_pfs', 'right-use-pfs'],
          ['left_disable_reuse', 'left-disable-reuse'],
          ['right_disable_reuse', 'right-disable-reuse'],
          ['allow_untrusted_issuers', 'allow-untrusted'],
          ['allow_invalid_certs', 'allow-invalid'],
          ['allow_self_signed', 'allow-self-signed'],
          ['ct_enable', 'certificate-transparency'],
          ['ocsp_stapling', 'ocsp-stapling'],
          ['alpn_block', 'block-alpn'],
          ['sni_based_cert', 'sni-cert'],
          ['ip_based_cert', 'ip-cert'],
          ['only_custom_certs', 'custom-only'],
          ['no_fallback_bypass', 'no-fallback'],
          ['sni_filter_use_dns_cache', 'sni-dns-cache'],
          ['sni_filter_use_dns_domain_tree', 'sni-dns-tree'],
          ['failed_certcheck_replacement', 'failed-replacement'],
          ['failed_certcheck_override', 'failed-override'],
          ['sslkeylog', 'key-log'],
        ] as const;
        const booleanChanges: DraftChange[] = [];
        for (const [path, id] of booleanFields) {
          const select = this.renderRoot.querySelector<HTMLSelectElement>(`#tls-${id}-${entry.id}`);
          if (!select || (select.value !== 'true' && select.value !== 'false')) return undefined;
          booleanChanges.push({path: `tls_profiles.[${index}].${path}`, value: select.value === 'true'});
        }
        const helloTimeout = this.renderRoot.querySelector<HTMLInputElement>(`#tls-hello-timeout-${entry.id}`);
        const handshakeTimeout = this.renderRoot.querySelector<HTMLInputElement>(`#tls-handshake-timeout-${entry.id}`);
        const ocspMode = this.renderRoot.querySelector<HTMLSelectElement>(`#tls-ocsp-mode-${entry.id}`);
        const staplingMode = this.renderRoot.querySelector<HTMLSelectElement>(`#tls-ocsp-stapling-mode-${entry.id}`);
        const warningPorts = this.renderRoot.querySelector<HTMLInputElement>(`#tls-warning-ports-${entry.id}`);
        const overrideTimeout = this.renderRoot.querySelector<HTMLInputElement>(`#tls-failed-override-timeout-${entry.id}`);
        const overrideTimeoutType = this.renderRoot.querySelector<HTMLSelectElement>(
          `#tls-failed-override-timeout-type-${entry.id}`,
        );
        const clientAction = this.renderRoot.querySelector<HTMLSelectElement>(`#tls-client-action-${entry.id}`);
        const alerts = this.renderRoot.querySelector<HTMLSelectElement>(`#tls-alerts-${entry.id}`);
        const bypassMode = this.renderRoot.querySelector<HTMLSelectElement>(`#tls-write-sni-${entry.id}-mode`);
        const bypassInput = this.renderRoot.querySelector<HTMLTextAreaElement>(`#tls-write-sni-${entry.id}-value`);
        const helloValue = helloTimeout?.valueAsNumber ?? Number.NaN;
        const handshakeValue = handshakeTimeout?.valueAsNumber ?? Number.NaN;
        const overrideTimeoutValue = overrideTimeout?.valueAsNumber ?? Number.NaN;
        const warningPortValues = (warningPorts?.value ?? '').split(',')
          .map(value => value.trim()).filter(Boolean).map(Number);
        if (!helloTimeout || !handshakeTimeout || !ocspMode || !staplingMode || !warningPorts ||
            !overrideTimeout || !overrideTimeoutType || !clientAction || !alerts || !bypassMode || !bypassInput ||
            !Number.isInteger(helloValue) || helloValue < 1 || helloValue > 2147483647 ||
            !Number.isInteger(handshakeValue) || handshakeValue < 1 || handshakeValue > 2147483647 ||
            !['0', '1', '2'].includes(ocspMode.value) || !['0', '1', '2'].includes(staplingMode.value) ||
            !Number.isInteger(overrideTimeoutValue) || overrideTimeoutValue < 1 || overrideTimeoutValue > 2147483647 ||
            !['0', '1'].includes(overrideTimeoutType.value) || warningPortValues.length > 256 ||
            !warningPortValues.every(value => Number.isInteger(value) && value >= 0 && value <= 65535) ||
            new Set(warningPortValues).size !== warningPortValues.length ||
            !['block_or_replacement', 'empty_client_cert', 'tls_bypass', 'use_configured'].includes(clientAction.value) ||
            !['all', 'unusual', 'mute'].includes(alerts.value) ||
            !['unchanged', 'replace', 'clear'].includes(bypassMode.value)) {
          this.draftError = 'TLS timeouts and policy selections are invalid.';
          return undefined;
        }
        let bypassReplacement: string[] | undefined;
        if (bypassMode.value === 'replace') {
          let parsed: unknown;
          try {
            parsed = JSON.parse(bypassInput.value);
          } catch {
            parsed = undefined;
          }
          if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > 256 ||
              !parsed.every(item => typeof item === 'string' && item.length > 0 &&
                item.length <= 1024 && !item.includes('\0')) ||
              new Set(parsed).size !== parsed.length) {
            this.draftError = 'SNI bypass replacement must be a unique, non-empty JSON string array.';
            return undefined;
          }
          bypassReplacement = parsed as string[];
        }
        return [
          {path: `tls_profiles.[${index}].name`, value: normalizedName},
          ...renameChanges,
          ...booleanChanges,
          {path: `tls_profiles.[${index}].ocsp_mode`, value: Number(ocspMode.value)},
          {path: `tls_profiles.[${index}].ocsp_stapling_mode`, value: Number(staplingMode.value)},
          {path: `tls_profiles.[${index}].redirect_warning_ports`, value: warningPortValues},
          {path: `tls_profiles.[${index}].failed_certcheck_override_timeout`, value: overrideTimeoutValue},
          {path: `tls_profiles.[${index}].failed_certcheck_override_timeout_type`, value: Number(overrideTimeoutType.value)},
          {path: `tls_profiles.[${index}].client_hello_timeout`, value: helloValue},
          {path: `tls_profiles.[${index}].handshake_timeout`, value: handshakeValue},
          {path: `tls_profiles.[${index}].client_cert_action`, value: clientAction.value},
          {path: `tls_profiles.[${index}].alerts`, value: alerts.value},
          ...(bypassMode.value === 'replace'
            ? [{path: `tls_profiles.[${index}].sni_filter_bypass`, value: bypassReplacement!}]
            : bypassMode.value === 'clear'
              ? [{path: `tls_profiles.[${index}].sni_filter_bypass`, value: []}]
              : []),
        ];
      }
      if (profile.content) {
        const profiles = this.snapshot.profiles.filter(item => item.content !== null);
        const index = profiles.findIndex(item => item.id === entry.id);
        if (index < 0) return undefined;
        const booleanFields = [
          ['write_payload', 'write-payload'],
          ['webhook_enable', 'webhook'],
          ['webhook_lock_traffic', 'webhook-lock'],
          ['ja4_tls_ch', 'ja4-client'],
          ['ja4_tls_ch_ignore_sni', 'ja4-ignore-sni'],
          ['ja4_tls_sh', 'ja4-server'],
          ['ja4_http', 'ja4-http'],
        ] as const;
        const changes: DraftChange[] = [];
        for (const [path, id] of booleanFields) {
          const select = this.renderRoot.querySelector<HTMLSelectElement>(`#content-${id}-${entry.id}`);
          if (!select || (select.value !== 'true' && select.value !== 'false')) return undefined;
          changes.push({path: `content_profiles.[${index}].${path}`, value: select.value === 'true'});
        }
        const format = this.renderRoot.querySelector<HTMLSelectElement>(`#content-format-${entry.id}`);
        const filterMode = this.renderRoot.querySelector<HTMLSelectElement>(`#content-write-filter-${entry.id}-mode`);
        const filterInput = this.renderRoot.querySelector<HTMLTextAreaElement>(`#content-write-filter-${entry.id}-value`);
        if (!format || !filterMode || !filterInput ||
            !['smcap', 'pcap', 'pcap_single'].includes(format.value) ||
            !['unchanged', 'replace', 'clear'].includes(filterMode.value)) {
          this.draftError = 'Content capture format is invalid.';
          return undefined;
        }
        const filterReplacement = filterInput.value;
        if (filterMode.value === 'replace' &&
            (filterReplacement.length === 0 || filterReplacement.length > 65536 || filterReplacement.includes('\0'))) {
          this.draftError = 'A session-filter replacement up to 65536 characters is required.';
          return undefined;
        }
        return [
          {path: `content_profiles.[${index}].name`, value: normalizedName},
          ...renameChanges,
          ...changes,
          {path: `content_profiles.[${index}].write_format`, value: format.value},
          ...(filterMode.value === 'replace'
            ? [{path: `content_profiles.[${index}].rules_session_filter`, value: filterReplacement}]
            : filterMode.value === 'clear'
              ? [{path: `content_profiles.[${index}].rules_session_filter`, value: ''}]
              : []),
        ];
      }
      if (profile.ssh) {
        const profiles = this.snapshot.profiles.filter(item => item.ssh !== null);
        const index = profiles.findIndex(item => item.id === entry.id);
        if (index < 0) return undefined;
        const policy = this.renderRoot.querySelector<HTMLSelectElement>(`#ssh-host-key-policy-${entry.id}`);
        const hostKeyMode = this.renderRoot.querySelector<HTMLSelectElement>(`#ssh-write-host-key-${entry.id}-mode`);
        const hostKeyValue = this.renderRoot.querySelector<HTMLInputElement>(`#ssh-write-host-key-${entry.id}-value`);
        if (!policy || !hostKeyMode || !hostKeyValue ||
            !['insecure', 'accept-new', 'strict'].includes(policy.value) ||
            !['unchanged', 'replace', 'clear'].includes(hostKeyMode.value)) {
          this.draftError = 'SSH host-key policy is invalid.';
          return undefined;
        }
        const replacement = hostKeyValue.value.trim();
        if (hostKeyMode.value === 'replace' &&
            (replacement.length === 0 || replacement.length > 1024 || /[\u0000-\u001f\u007f]/u.test(replacement))) {
          this.draftError = 'A replacement host-key path up to 1024 characters is required.';
          return undefined;
        }
        const actions = [
          ['shell', 'shell'],
          ['exec', 'exec'],
          ['subsystem', 'subsystem'],
          ['pty', 'pty'],
          ['environment', 'environment'],
          ['local_forward', 'local-forward'],
          ['remote_forward', 'remote-forward'],
          ['x11', 'x11'],
          ['agent', 'agent'],
        ] as const;
        const changes: DraftChange[] = [];
        for (const [path, id] of actions) {
          const select = this.renderRoot.querySelector<HTMLSelectElement>(`#ssh-${id}-${entry.id}`);
          if (!select || (select.value !== 'pass' && select.value !== 'reject')) return undefined;
          changes.push({path: `ssh_profiles.[${index}].${path}`, value: select.value});
        }
        return [
          {path: `ssh_profiles.[${index}].name`, value: normalizedName},
          ...renameChanges,
          {path: `ssh_profiles.[${index}].hostkey_policy`, value: policy.value},
          ...changes,
          ...(hostKeyMode.value === 'replace'
            ? [{path: `ssh_profiles.[${index}].host_key`, value: replacement}]
            : hostKeyMode.value === 'clear'
              ? [{path: `ssh_profiles.[${index}].host_key`, value: ''}]
              : []),
        ];
      }
      if (profile.script) {
        const profiles = this.snapshot.profiles.filter(item => item.script !== null);
        const index = profiles.findIndex(item => item.id === entry.id);
        const runtime = this.renderRoot.querySelector<HTMLSelectElement>(`#script-runtime-${entry.id}`);
        const moduleMode = this.renderRoot.querySelector<HTMLSelectElement>(`#script-write-module-${entry.id}-mode`);
        const moduleValue = this.renderRoot.querySelector<HTMLInputElement>(`#script-write-module-${entry.id}-value`);
        if (index < 0 || !runtime || !moduleMode || !moduleValue ||
            !['python', 'go', 'unknown'].includes(runtime.value) ||
            !['unchanged', 'replace', 'clear'].includes(moduleMode.value)) {
          this.draftError = 'Script runtime is invalid.';
          return undefined;
        }
        const replacement = moduleValue.value.trim();
        if (moduleMode.value === 'replace' &&
            (replacement.length === 0 || replacement.length > 1024 || /[\u0000-\u001f\u007f]/u.test(replacement))) {
          this.draftError = 'A replacement script module path up to 1024 characters is required.';
          return undefined;
        }
        const configuredType = runtime.value === 'python' ? '0' : runtime.value === 'go' ? '1' : '-1';
        return [
          {path: `script_profiles.[${index}].name`, value: normalizedName},
          ...renameChanges,
          {path: `script_profiles.[${index}].type`, value: configuredType},
          ...(moduleMode.value === 'replace'
            ? [{path: `script_profiles.[${index}].script-file`, value: replacement}]
            : moduleMode.value === 'clear'
              ? [{path: `script_profiles.[${index}].script-file`, value: ''}]
              : []),
        ];
      }
      if (profile.authentication) {
        const profiles = this.snapshot.profiles.filter(item => item.authentication !== null);
        const index = profiles.findIndex(item => item.id === entry.id);
        const authenticate = this.renderRoot.querySelector<HTMLSelectElement>(`#auth-authenticate-${entry.id}`);
        const resolve = this.renderRoot.querySelector<HTMLSelectElement>(`#auth-resolve-${entry.id}`);
        if (index < 0 || !authenticate || !resolve ||
            ![authenticate.value, resolve.value].every(value => value === 'true' || value === 'false')) {
          return undefined;
        }
        return [
          {path: `auth_profiles.[${index}].name`, value: normalizedName},
          ...renameChanges,
          {path: `auth_profiles.[${index}].authenticate`, value: authenticate.value === 'true'},
          {path: `auth_profiles.[${index}].resolve`, value: resolve.value === 'true'},
        ];
      }
      if (profile.detection) {
        const profiles = this.snapshot.profiles.filter(item => item.detection !== null);
        const index = profiles.findIndex(item => item.id === entry.id);
        const mode = this.renderRoot.querySelector<HTMLSelectElement>(`#detection-mode-${entry.id}`);
        const engines = this.renderRoot.querySelector<HTMLSelectElement>(`#detection-engines-${entry.id}`);
        const knowledgeBase = this.renderRoot.querySelector<HTMLSelectElement>(`#detection-kb-${entry.id}`);
        const modeValue = Number(mode?.value);
        if (index < 0 || !mode || !engines || !knowledgeBase ||
            !Number.isInteger(modeValue) || modeValue < 0 || modeValue > 2 ||
            ![engines.value, knowledgeBase.value].every(value => value === 'true' || value === 'false')) {
          return undefined;
        }
        return [
          {path: `detection_profiles.[${index}].name`, value: normalizedName},
          ...renameChanges,
          {path: `detection_profiles.[${index}].mode`, value: modeValue},
          {path: `detection_profiles.[${index}].engines_enabled`, value: engines.value === 'true'},
          {path: `detection_profiles.[${index}].kb_enabled`, value: knowledgeBase.value === 'true'},
        ];
      }
      if (profile.dns) {
        const profiles = this.snapshot.profiles.filter(item => item.dns !== null);
        const index = profiles.findIndex(item => item.id === entry.id);
        const match = this.renderRoot.querySelector<HTMLSelectElement>(`#dns-match-${entry.id}`);
        const randomize = this.renderRoot.querySelector<HTMLSelectElement>(`#dns-randomize-${entry.id}`);
        const cached = this.renderRoot.querySelector<HTMLSelectElement>(`#dns-cached-${entry.id}`);
        if (index < 0 || !match || !randomize || !cached ||
            ![match.value, randomize.value, cached.value].every(value => value === 'true' || value === 'false')) {
          return undefined;
        }
        return [
          {path: `alg_dns_profiles.[${index}].name`, value: normalizedName},
          ...renameChanges,
          {path: `alg_dns_profiles.[${index}].match_request_id`, value: match.value === 'true'},
          {path: `alg_dns_profiles.[${index}].randomize_id`, value: randomize.value === 'true'},
          {path: `alg_dns_profiles.[${index}].cached_responses`, value: cached.value === 'true'},
        ];
      }
    }
    return undefined;
  }

  private systemSettingsDraftChanges(): ReadonlyArray<DraftChange> | undefined {
    const changes: DraftChange[] = [];
    for (const [path, id] of systemBooleanFields) {
      const select = this.renderRoot.querySelector<HTMLSelectElement>(`#settings-${id}`);
      if (!select || (select.value !== 'true' && select.value !== 'false')) return undefined;
      changes.push({path: `settings.${path}`, value: select.value === 'true'});
    }
    const siftLoredMode = this.renderRoot.querySelector<HTMLSelectElement>('#settings-webhook-sift-lored-mode');
    if (!siftLoredMode || !['disabled', 'optional', 'required'].includes(siftLoredMode.value)) {
      this.draftError = 'Sift LoreD mode is invalid.';
      return undefined;
    }
    changes.push({path: 'settings.webhook.sift_lored_mode', value: siftLoredMode.value});
    for (const [path, id] of systemWorkerFields) {
      const input = this.renderRoot.querySelector<HTMLInputElement>(`#settings-worker-${id}`);
      const value = input?.valueAsNumber ?? Number.NaN;
      if (!input || !Number.isInteger(value) || value < -1 || value > 4096) {
        this.draftError = 'Worker counts must be integers from -1 to 4096.';
        return undefined;
      }
      changes.push({path: `settings.${path}`, value});
    }
    for (const [path, id, maximum] of systemNumericFields) {
      const input = this.renderRoot.querySelector<HTMLInputElement>(`#settings-${id}`);
      const value = input?.valueAsNumber ?? Number.NaN;
      if (!input || !Number.isInteger(value) || value < 0 || value > maximum) {
        this.draftError = 'Ports and status TTLs must be integers within their documented ranges.';
        return undefined;
      }
      changes.push({path: `settings.${path}`, value});
    }
    const syslogFamily = this.renderRoot.querySelector<HTMLSelectElement>('#settings-logging-syslog-family');
    if (!syslogFamily || (syslogFamily.value !== '4' && syslogFamily.value !== '6')) return undefined;
    changes.push({path: 'settings.syslog_family', value: Number(syslogFamily.value)});
    const nameserversInput = this.renderRoot.querySelector<HTMLInputElement>('#settings-nameservers');
    const quickPortsInput = this.renderRoot.querySelector<HTMLInputElement>('#settings-udp-quick-ports');
    const allowedIpsInput = this.renderRoot.querySelector<HTMLInputElement>('#settings-api-allowed-ips');
    if (!nameserversInput || !quickPortsInput || !allowedIpsInput) return undefined;
    const splitList = (value: string) => value.split(',').map(item => item.trim()).filter(Boolean);
    const nameservers = splitList(nameserversInput.value);
    const quickPorts = splitList(quickPortsInput.value);
    const allowedIps = splitList(allowedIpsInput.value);
    if (nameservers.length > 256 || new Set(nameservers).size !== nameservers.length ||
        nameservers.some(item => !/^[A-Za-z0-9:._-]{1,128}$/u.test(item)) ||
        quickPorts.length > 256 || new Set(quickPorts).size !== quickPorts.length ||
        quickPorts.some(item => !/^\d{1,5}$/u.test(item) || Number(item) > 65535) ||
        allowedIps.length > 256 || new Set(allowedIps).size !== allowedIps.length ||
        allowedIps.some(item => !/^[A-Za-z0-9:._/-]{1,128}$/u.test(item))) {
      this.draftError = 'Nameservers, API allowlists, and UDP quick ports must be unique, bounded values.';
      return undefined;
    }
    changes.push({path: 'settings.nameservers', value: nameservers});
    changes.push({path: 'settings.udp_quick_ports', value: quickPorts});
    changes.push({path: 'settings.http_api.allowed_ips', value: allowedIps});
    const apiKeyTimeout = this.renderRoot.querySelector<HTMLInputElement>('#settings-api-key-timeout');
    const apiPort = this.renderRoot.querySelector<HTMLInputElement>('#settings-api-port');
    const apiKeyTimeoutValue = apiKeyTimeout?.valueAsNumber ?? Number.NaN;
    const apiPortValue = apiPort?.valueAsNumber ?? Number.NaN;
    if (!apiKeyTimeout || !apiPort || !Number.isInteger(apiKeyTimeoutValue) ||
        apiKeyTimeoutValue < 1 || apiKeyTimeoutValue > 4294967295 ||
        !Number.isInteger(apiPortValue) || apiPortValue < 1025 || apiPortValue > 65534) {
      this.draftError = 'API token TTL and listener port are outside their supported ranges.';
      return undefined;
    }
    changes.push({path: 'settings.http_api.key_timeout', value: apiKeyTimeoutValue});
    changes.push({path: 'settings.http_api.port', value: apiPortValue});
    for (const [path, id, minimum, maximum] of systemTuningFields) {
      const input = this.renderRoot.querySelector<HTMLInputElement>(`#settings-tuning-${id}`);
      const value = input?.valueAsNumber ?? Number.NaN;
      if (!input || !Number.isInteger(value) || value < minimum || value > maximum) {
        this.draftError = 'Performance tuning values are outside their supported ranges.';
        return undefined;
      }
      changes.push({path: `settings.tuning.${path}`, value});
    }
    const siftPayloadLimit = this.renderRoot.querySelector<HTMLInputElement>('#settings-webhook-sift-payload-limit');
    const siftPayloadLimitValue = siftPayloadLimit?.valueAsNumber ?? Number.NaN;
    if (!siftPayloadLimit || !Number.isInteger(siftPayloadLimitValue) ||
        siftPayloadLimitValue < 1 || siftPayloadLimitValue > 1073741824) {
      this.draftError = 'Sift payload limit must be an integer from 1 to 1073741824 bytes.';
      return undefined;
    }
    changes.push({path: 'settings.webhook.sift_payload_limit_per_direction', value: siftPayloadLimitValue});
    const apiKeysMode = this.renderRoot.querySelector<HTMLSelectElement>('#settings-api-keys-mode');
    const apiKeysInput = this.renderRoot.querySelector<HTMLInputElement>('#settings-api-keys-value');
    if (!apiKeysMode || !apiKeysInput || !['unchanged', 'replace', 'clear'].includes(apiKeysMode.value)) {
      return undefined;
    }
    if (apiKeysMode.value === 'clear') {
      changes.push({path: 'settings.http_api.keys', value: []});
    } else if (apiKeysMode.value === 'replace') {
      let keys: unknown;
      try {
        keys = JSON.parse(apiKeysInput.value);
      } catch {
        keys = undefined;
      }
      if (!Array.isArray(keys) || keys.length === 0 || keys.length > 256 ||
          !keys.every(key => typeof key === 'string' && key.length > 0 &&
            key.length <= 65536 && !key.includes('\0'))) {
        this.draftError = 'API key replacement must be a non-empty JSON string array.';
        return undefined;
      }
      changes.push({path: 'settings.http_api.keys', value: keys as string[]});
    }
    const writeOnlyFields = [
      ['webhook.url', 'webhook-url', 'url'], ['syslog_server', 'syslog-server', 'host'],
      ['write_payload_dir', 'payload-directory', 'path'], ['log_file', 'log-file', 'path'],
      ['sslkeylog_file', 'tls-key-log-file', 'path'], ['certs_path', 'certificates-path', 'path'],
      ['certs_ca_key_password', 'certificate-password', 'secret'],
      ['certs_ctlog', 'certificate-transparency-log', 'file'],
      ['ca_bundle_path', 'ca-bundle-path', 'path'], ['ca_bundle_file', 'ca-bundle-file', 'file'],
      ['admin.group', 'admin-group', 'text'], ['messages_dir', 'messages-directory', 'path'],
      ['write_payload_file_prefix', 'payload-prefix', 'filename'],
      ['write_payload_file_suffix', 'payload-suffix', 'filename'],
      ['cli.enable_password', 'cli-password', 'secret'],
      ['web_rating.wot_key', 'web-rating-key', 'secret'],
      ['http_api.bind_address', 'api-bind-address', 'ipv4'],
      ['http_api.bind_interface', 'api-bind-interface', 'host'],
      ['webhook.sift_url', 'webhook-sift-url', 'url'],
      ['webhook.sift_tenant_id', 'webhook-sift-tenant', 'text'],
      ['webhook.sift_instance_id', 'webhook-sift-instance', 'text'],
      ['webhook.hostid', 'webhook-host-id', 'text'],
      ['webhook.bind_interface', 'webhook-bind-interface', 'host'],
    ] as const;
    for (const [path, id, kind] of writeOnlyFields) {
      const mode = this.renderRoot.querySelector<HTMLSelectElement>(`#settings-write-${id}-mode`);
      const input = this.renderRoot.querySelector<HTMLInputElement>(`#settings-write-${id}-value`);
      if (!mode || !input || !['unchanged', 'replace', 'clear'].includes(mode.value)) return undefined;
      if (mode.value === 'unchanged') continue;
      if (mode.value === 'clear') {
        changes.push({path: `settings.${path}`, value: ''});
        continue;
      }
      const replacement = input.value;
      let valid = replacement.length > 0 && replacement.length <= 1024 &&
        !/[\u0000-\u001f\u007f]/u.test(replacement);
      if (kind === 'path') valid = valid && replacement.startsWith('/');
      if (kind === 'host') valid = valid && /^[A-Za-z0-9:._-]{1,128}$/u.test(replacement);
      if (kind === 'ipv4') {
        const octets = replacement.split('.');
        valid = valid && octets.length === 4 && octets.every(octet =>
          /^\d{1,3}$/u.test(octet) && Number(octet) <= 255 && String(Number(octet)) === octet,
        );
      }
      if (kind === 'filename') valid = valid && replacement.length <= 128 && !/[\\/]/u.test(replacement);
      if (kind === 'url' && valid) {
        try {
          const url = new URL(replacement);
          valid = ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password;
        } catch {
          valid = false;
        }
      }
      if (!valid) {
        this.draftError = 'A write-only replacement is invalid for its configuration field.';
        return undefined;
      }
      changes.push({path: `settings.${path}`, value: replacement});
    }
    if (this.snapshot?.debug) {
      for (const [path, id] of debugFields) {
        const select = this.renderRoot.querySelector<HTMLSelectElement>(`#debug-${id}`);
        if (!select || (select.value !== 'true' && select.value !== 'false')) return undefined;
        changes.push({path: `debug.${path}`, value: select.value === 'true'});
      }
      for (const [index, override] of this.snapshot.debug.moduleOverrides.entries()) {
        const id = `debug-module-${index}`;
        if (override.kind === 'boolean') {
          const select = this.renderRoot.querySelector<HTMLSelectElement>(`#${id}`);
          if (!select || (select.value !== 'true' && select.value !== 'false')) return undefined;
          changes.push({path: `debug.log.${override.name}`, value: select.value === 'true'});
          continue;
        }
        const input = this.renderRoot.querySelector<HTMLInputElement>(`#${id}`);
        if (!input) return undefined;
        if (override.kind === 'integer') {
          const value = input.valueAsNumber;
          if (!Number.isSafeInteger(value) || value < -2147483648 || value > 2147483647) {
            this.draftError = `${override.name} debug override must be a 32-bit integer.`;
            return undefined;
          }
          changes.push({path: `debug.log.${override.name}`, value});
          continue;
        }
        if (input.value.length > 32 || /[\u0000-\u001f\u007f]/u.test(input.value)) {
          this.draftError = `${override.name} debug override is invalid.`;
          return undefined;
        }
        changes.push({path: `debug.log.${override.name}`, value: input.value});
      }
    }
    return changes;
  }

  private captureSettingsDraftChanges(): ReadonlyArray<DraftChange> | undefined {
    const changes: DraftChange[] = [];
    for (const [path, id] of captureBooleanFields) {
      const select = this.renderRoot.querySelector<HTMLSelectElement>(`#captures-${id}`);
      if (!select || (select.value !== 'true' && select.value !== 'false')) return undefined;
      changes.push({path: `captures.${path}`, value: select.value === 'true'});
    }
    const format = this.renderRoot.querySelector<HTMLSelectElement>('#captures-local-format');
    const tunnelType = this.renderRoot.querySelector<HTMLSelectElement>('#captures-tunnel-type');
    const greFormat = this.renderRoot.querySelector<HTMLSelectElement>('#captures-gre-format');
    const quota = this.renderRoot.querySelector<HTMLInputElement>('#captures-local-quota');
    const ttl = this.renderRoot.querySelector<HTMLInputElement>('#captures-remote-ttl');
    const quotaValue = quota?.valueAsNumber ?? Number.NaN;
    const ttlValue = ttl?.valueAsNumber ?? Number.NaN;
    if (!format || !tunnelType || !greFormat || !quota || !ttl ||
        !['pcap_single', 'pcap', 'smcap'].includes(format.value) ||
        tunnelType.value !== 'gre' ||
        !['traffic', 'pcapng'].includes(greFormat.value) ||
        !Number.isInteger(quotaValue) || quotaValue < 0 || quotaValue > 1048576 ||
        !Number.isInteger(ttlValue) || ttlValue < 0 || ttlValue > 255) {
      this.draftError = 'Capture format, quota, or tunnel TTL is invalid.';
      return undefined;
    }
    changes.push(
      {path: 'captures.local.format', value: format.value},
      {path: 'captures.local.pcap_quota', value: quotaValue},
      {path: 'captures.remote.tun_type', value: tunnelType.value},
      {path: 'captures.remote.gre_format', value: greFormat.value},
      {path: 'captures.remote.tun_ttl', value: ttlValue},
    );
    const writeOnlyFields = [
      ['local.dir', 'local-directory', 'path'],
      ['local.file_prefix', 'local-prefix', 'filename'],
      ['local.file_suffix', 'local-suffix', 'filename'],
      ['remote.tun_dst', 'remote-destination', 'host'],
      ['remote.bind_interface', 'bind-interface', 'interface'],
    ] as const;
    for (const [path, id, kind] of writeOnlyFields) {
      const mode = this.renderRoot.querySelector<HTMLSelectElement>(`#captures-write-${id}-mode`);
      const input = this.renderRoot.querySelector<HTMLInputElement>(`#captures-write-${id}-value`);
      if (!mode || !input || !['unchanged', 'replace', 'clear'].includes(mode.value)) return undefined;
      if (mode.value === 'unchanged') continue;
      if (mode.value === 'clear') {
        changes.push({path: `captures.${path}`, value: ''});
        continue;
      }
      const replacement = input.value;
      let valid = replacement.length > 0 && replacement.length <= 1024 &&
        !/[\u0000-\u001f\u007f]/u.test(replacement);
      if (kind === 'path') valid = valid && replacement.startsWith('/');
      if (kind === 'filename') valid = valid && replacement.length <= 128 && !/[\\/]/u.test(replacement);
      if (kind === 'host') valid = valid && /^[A-Za-z0-9:._-]{1,128}$/u.test(replacement);
      if (kind === 'interface') valid = valid && /^[A-Za-z0-9:._-]{1,128}$/u.test(replacement);
      if (!valid) {
        this.draftError = 'A write-only capture replacement is invalid for its field.';
        return undefined;
      }
      changes.push({path: `captures.${path}`, value: replacement});
    }
    return changes;
  }

  private handleKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape' && this.drawers.length > 0) {
      event.preventDefault();
      this.requestCloseDrawer(this.drawers.length - 1);
      return;
    }
    if (event.key === 'Escape' && this.searchQuery) {
      event.preventDefault();
      this.searchQuery = '';
      this.activeSection = this.searchReturnSection;
      return;
    }
    if (event.key !== 'Tab' || this.drawers.length === 0) return;
    const active = this.renderRoot.querySelectorAll<HTMLElement>('.drawer').item(this.drawers.length - 1);
    if (!active) return;
    const focusable = [...active.querySelectorAll<HTMLElement>(
      'button:not([disabled]), input:not([disabled]), select:not([disabled]), ' +
      'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    )];
    if (focusable.length === 0) { event.preventDefault(); active.focus(); return; }
    const current = this.shadowRoot?.activeElement;
    const index = focusable.indexOf(current as HTMLElement);
    if (event.shiftKey && index <= 0) {
      event.preventDefault();
      focusable.at(-1)?.focus();
    } else if (!event.shiftKey && (index < 0 || index === focusable.length - 1)) {
      event.preventDefault();
      focusable[0]?.focus();
    }
  }

  private renderDraftReview() {
    const changes = this.workspaceDraft?.changes ?? [];
    const structuralOperations = this.workspaceDraft?.structuralOperations ?? [];
    const pendingCount = changes.length + structuralOperations.length;
    const commitReady = this.draftPreflight?.commitAvailable && this.draftValidation &&
      this.draftValidation.draftVersion === this.draftVersion &&
      this.draftValidation.baseRevision === this.draftPreflight.baseRevision &&
      this.draftValidation.validatedOperations === pendingCount;
    return html`
      <div class="content" tabindex="0">
        <div class="section-head">
          <div>
            <h2>Workspace draft</h2>
            <p>Version ${this.draftVersion} · ${pendingCount} pending operations</p>
          </div>
          <button class="secondary danger-button" type="button"
            ?disabled=${pendingCount === 0 || this.draftSaving || this.draftValidating ||
              this.draftCommitting}
            @click=${() => this.discardDraft()}>
            ${this.draftSaving
              ? 'Discarding…'
              : this.discardDraftArmed
                ? `Confirm discard ${pendingCount} operations`
                : 'Discard draft'}
          </button>
        </div>
        ${this.draftError ? html`<div class="error" role="alert">${this.draftError}</div>` : nothing}
        ${pendingCount > 0 ? html`
          <section class="preflight" aria-label="Draft preflight">
            <div class="preflight-heading">
              <h3>Validation and impact preflight</h3>
              <div class="preflight-actions">
                <button class="secondary" type="button"
                  ?disabled=${!this.draftPreflight?.validationAvailable || this.draftValidating ||
                    this.draftCommitting}
                  @click=${() => this.validateDraft()}>
                  ${this.draftValidating ? 'Validating…' : 'Validate with Smithproxy'}
                </button>
                <button class="primary" type="button"
                  ?disabled=${!commitReady || this.draftCommitting || this.draftSaving ||
                    this.draftValidating}
                  @click=${() => this.commitDraft()}>
                  ${this.draftCommitting
                    ? 'Committing…'
                    : this.draftCommitArmed
                      ? `Confirm atomic commit · ${pendingCount}`
                      : 'Commit configuration'}
                </button>
              </div>
            </div>
            ${this.draftPreflight ? html`
              <div class="preflight-grid">
                <div class="preflight-check">
                  <small>GUI schema validation</small><strong class="runtime-state success">Valid</strong>
                </div>
                <div class="preflight-check">
                  <small>Smithproxy validation</small>
                  ${this.draftValidation ? html`
                    <strong class="runtime-state success">Validated</strong>
                  ` : this.draftPreflight.validationAvailable ? html`
                    <strong class="runtime-state warning">Ready</strong>
                  ` : html`
                    <strong class="runtime-state warning">Unavailable</strong>
                  `}
                </div>
                <div class="preflight-check">
                  <small>Atomic commit</small>
                  <strong class="runtime-state ${commitReady ? 'success' : 'warning'}">
                    ${commitReady ? 'Ready' : this.draftPreflight.commitAvailable
                      ? 'Validation required' : 'Blocked'}
                  </strong>
                </div>
              </div>
              <div class="preflight-sections" aria-label="Affected configuration sections">
                ${this.draftPreflight.sections.map(section => html`
                  <span class="preflight-section">
                    ${section.name.replaceAll('_', ' ')} · ${section.changeCount}
                    ${section.sensitiveChangeCount > 0 ? ` · ${section.sensitiveChangeCount} write-only` : ''}
                  </span>
                `)}
              </div>
              ${this.draftPreflight.blockers.length > 0 ? html`
                <ul class="preflight-blockers">
                  ${this.draftPreflight.blockers.map(blocker => html`<li>${blocker.message}</li>`)}
                </ul>
              ` : nothing}
              ${this.draftValidation ? html`
                <p class="metric-note" role="status">
                  Smithproxy validated ${this.draftValidation.validatedOperations} operations ·
                  ${this.draftValidation.warningCount} warnings ·
                  restart ${this.draftValidation.restart.replaceAll('-', ' ')}.
                </p>
              ` : this.draftValidationError ? html`
                <div class="metrics-message" role="alert">${this.draftValidationError}</div>
              ` : nothing}
              <p class="metric-note">
                ${this.draftPreflight.sensitiveChangeCount} of ${this.draftPreflight.changeCount}
                changes contain write-only values. Their values remain redacted.
              </p>
            ` : !this.draftPreflightAvailable ? html`
              <div class="metrics-message">The current GUI core does not advertise draft preflight.</div>
            ` : this.draftPreflightError ? html`
              <div class="metrics-message" role="alert">${this.draftPreflightError}</div>
            ` : html`
              <div class="metrics-message" role="status">Loading secure preflight…</div>
            `}
          </section>
        ` : nothing}
        ${this.draftCommitResult ? html`
          <div class="metrics-message" role="status">
            Atomic commit completed: ${this.draftCommitResult.committedOperations} operations ·
            ${this.draftCommitResult.warningCount} warnings · restart
            ${this.draftCommitResult.restart.replaceAll('-', ' ')}.
            ${this.draftCommitResult.refreshJobId
              ? 'The configuration refresh job is being tracked.'
              : 'Configuration refresh tracking is unavailable.'}
          </div>
        ` : this.draftCommitError ? html`
          <div class="error" role="alert">${this.draftCommitError}</div>
        ` : nothing}
        ${pendingCount === 0 ? html`
          <div class="empty-state">
            <h2>No pending changes</h2>
            <p>Edits from policy and referenced-object drawers will appear here before validation and commit.</p>
          </div>
        ` : html`
          <div class="table" role="table" aria-label="Pending draft changes">
            <div class="draft-row heading" role="row">
              <span role="columnheader">Configuration path</span>
              <span role="columnheader">Draft value</span>
              <span role="columnheader">Action</span>
            </div>
            ${changes.map(change => {
              const target = this.draftTargetForPath(change.path);
              return html`<div class="draft-row" role="row">
                <span class="draft-path" role="cell">${change.path}</span>
                <span class="draft-value" role="cell">${this.draftValueSummary(change.path, change.value)}</span>
                <span class="draft-actions" role="cell">
                  ${target ? html`
                    <button class="secondary" type="button"
                      aria-label=${`Edit ${change.path}`}
                      @click=${(event: MouseEvent) =>
                        this.openObjectDrawer(target, event.currentTarget as HTMLElement)}>Edit</button>
                  ` : nothing}
                  <button class="secondary" type="button"
                    aria-label=${`Remove ${change.path} from draft`}
                    ?disabled=${this.draftSaving || this.draftValidating || this.draftCommitting}
                    @click=${() => this.removeDraftChange(change.path)}>Remove</button>
                </span>
              </div>`;
            })}
            ${structuralOperations.map(operation => html`
              <div class="draft-row" role="row">
                <span class="draft-path" role="cell">
                  ${operation.collection} · ${operation.op}
                </span>
                <span class="draft-value" role="cell">
                  ${operation.op === 'create'
                    ? `${typeof operation.fields['name'] === 'string'
                      ? operation.fields['name'] : operation.clientId} · ${Object.keys(operation.fields).length} fields`
                    : operation.entityId}
                </span>
                <span class="draft-actions" role="cell">
                  ${operation.op === 'create' && [
                    'address_objects', 'port_objects', 'proto_objects', 'policy',
                  ].includes(operation.collection) ? html`
                    <button class="secondary" type="button"
                      ?disabled=${!this.structuralDraftsAvailable}
                      @click=${(event: MouseEvent) => this.openDraftStructuralOperation(
                        operation.localId, event.currentTarget as HTMLElement,
                      )}>Edit</button>
                  ` : nothing}
                  <button class="secondary" type="button"
                    aria-label=${`Remove ${operation.op} operation ${operation.localId} from draft`}
                    ?disabled=${this.draftSaving || this.draftValidating || this.draftCommitting}
                    @click=${() => this.removeDraftOperation(operation.localId)}>Remove</button>
                </span>
              </div>
            `)}
          </div>
          <div class="scope-note section">
            This is a pending management draft only. It has not changed persistent or runtime Smithproxy configuration.
          </div>
        `}
      </div>
    `;
  }

  private renderPolicyList() {
    const overlayCounts = this.overlayCounts();
    return html`
      <div class="content" tabindex="0">
        <div class="section-head">
          <div><h2>Policies</h2><p>Traffic decisions and inspection behavior</p></div>
          <div class="structural-action">
            <button class="primary" type="button" ?disabled=${!this.structuralDraftsAvailable}
              aria-describedby="new-policy-blocker"
              @click=${(event: MouseEvent) => this.openNewPolicy(event.currentTarget as HTMLElement)}>
              New policy
            </button>
            <small id="new-policy-blocker">${this.structuralDraftsAvailable
              ? 'Creates an ordered operation in the shared workspace draft.'
              : 'Requires reviewed structural transactions and stable entity IDs.'}</small>
          </div>
        </div>
        <div class="table" role="group" aria-label="Policies">
          <div class="row heading" aria-hidden="true">
            <span>Name</span><span>Source</span><span>Destination</span><span>Action</span><span>Status</span>
          </div>
          ${this.snapshot?.policies.map((policy, index) => {
            const base = `policy.[${index}]`;
            const name = this.presentedValue(`${base}.name`, policy.name);
            const sources = this.presentedListValue(
              `${base}.src`, policy.sources.map(item => item.name), 'string',
            );
            const destinations = this.presentedListValue(
              `${base}.dst`, policy.destinations.map(item => item.name), 'string',
            );
            const action = this.presentedValue(`${base}.action`, policy.action);
            const enabled = !this.presentedValue(`${base}.disabled`, !policy.enabled);
            return html`<button class="row" type="button"
              @click=${(event: MouseEvent) => this.openPolicy(policy, event.currentTarget as HTMLElement)}>
              <strong>${name}</strong>
              <span>${this.referenceNameSummary(sources)}</span>
              <span>${this.referenceNameSummary(destinations)}</span>
              <span class="action">${action}</span>
              <span class="row-meta">
                <span class="status ${enabled ? '' : 'disabled'}">${enabled ? 'Enabled' : 'Disabled'}</span>
                ${this.renderPendingBadge('policy', policy.id)}
                ${this.renderOverlayBadge(`policy.[${index}].`, overlayCounts)}
              </span>
            </button>`;
          })}
        </div>
      </div>
    `;
  }

  private updateSearch(value: string): void {
    const query = value.slice(0, 128);
    if (!this.searchQuery && query) this.searchReturnSection = this.activeSection;
    this.searchQuery = query;
    this.activeSection = query ? 'Search' : this.searchReturnSection;
  }

  private searchMatches(values: ReadonlyArray<string | number>, query: string): boolean {
    return values.some(value => String(value).toLocaleLowerCase().includes(query));
  }

  private profileSearchValues(item: ProfileObject, prefix: string | undefined): ReadonlyArray<string | number> {
    const scalar = <T extends ConfigScalar>(field: string, fallback: T): T =>
      prefix ? this.presentedValue(`${prefix}${field}`, fallback) : fallback;
    const strings = (field: string, fallback: ReadonlyArray<string>): ReadonlyArray<string> =>
      prefix ? this.presentedListValue(`${prefix}${field}`, fallback, 'string') : fallback;
    const numbers = (field: string, fallback: ReadonlyArray<number>): ReadonlyArray<number> =>
      prefix ? this.presentedListValue(`${prefix}${field}`, fallback, 'number') : fallback;
    const booleanNumber = (field: string, fallback: boolean): number => Number(scalar(field, fallback));
    const values: Array<string | number> = [scalar('name', item.name), item.type];

    if (item.routing) values.push(
      ...strings('dnat_address', item.routing.destinationAddresses),
      ...strings('dnat_port', item.routing.destinationPorts),
      scalar('dnat_lb_method', item.routing.loadBalancingMethod),
      scalar('rewrite_sni', item.routing.rewriteSni),
      scalar('rewrite_sni_to', item.routing.rewriteSniTo),
      'destination address', 'destination port', 'load balancing', 'rewrite sni',
    );
    if (item.tls) values.push(
      booleanNumber('inspect', item.tls.inspect), booleanNumber('use_pfs', item.tls.usePfs),
      booleanNumber('left_use_pfs', item.tls.leftUsePfs),
      booleanNumber('right_use_pfs', item.tls.rightUsePfs),
      booleanNumber('left_disable_reuse', item.tls.leftDisableReuse),
      booleanNumber('right_disable_reuse', item.tls.rightDisableReuse),
      booleanNumber('allow_untrusted_issuers', item.tls.allowUntrustedIssuers),
      booleanNumber('allow_invalid_certs', item.tls.allowInvalidCertificates),
      booleanNumber('allow_self_signed', item.tls.allowSelfSigned),
      booleanNumber('ct_enable', item.tls.certificateTransparency),
      scalar('ocsp_mode', item.tls.ocspMode),
      booleanNumber('ocsp_stapling', item.tls.ocspStapling),
      scalar('ocsp_stapling_mode', item.tls.ocspStaplingMode),
      booleanNumber('alpn_block', item.tls.blockAlpn),
      booleanNumber('sni_based_cert', item.tls.sniBasedCertificates),
      booleanNumber('ip_based_cert', item.tls.ipBasedCertificates),
      booleanNumber('only_custom_certs', item.tls.onlyCustomCertificates),
      booleanNumber('no_fallback_bypass', item.tls.noFallbackBypass),
      booleanNumber('sni_filter_use_dns_cache', item.tls.sniFilterUsesDnsCache),
      booleanNumber('sni_filter_use_dns_domain_tree', item.tls.sniFilterUsesDnsDomainTree),
      ...numbers('redirect_warning_ports', item.tls.redirectWarningPorts),
      booleanNumber('failed_certcheck_replacement', item.tls.failedCertificateReplacement),
      booleanNumber('failed_certcheck_override', item.tls.failedCertificateOverride),
      scalar('failed_certcheck_override_timeout', item.tls.failedCertificateOverrideTimeout),
      scalar('failed_certcheck_override_timeout_type', item.tls.failedCertificateOverrideTimeoutType),
      booleanNumber('sslkeylog', item.tls.sslKeyLog),
      scalar('client_hello_timeout', item.tls.clientHelloTimeoutMs),
      scalar('handshake_timeout', item.tls.handshakeTimeoutMs),
      item.tls.sniBypassEntries, scalar('client_cert_action', item.tls.clientCertificateAction),
      scalar('alerts', item.tls.alerts),
      'inspection', 'pfs', 'certificate', 'ocsp', 'alpn', 'sni', 'alerts',
    );
    if (item.detection) values.push(
      scalar('mode', item.detection.mode),
      booleanNumber('engines_enabled', item.detection.enginesEnabled),
      booleanNumber('kb_enabled', item.detection.knowledgeBaseEnabled),
      'detection phase', 'l7 engines', 'knowledge base',
    );
    if (item.content) values.push(
      booleanNumber('write_payload', item.content.writePayload),
      scalar('write_format', item.content.writeFormat),
      booleanNumber('webhook_enable', item.content.webhookEnabled),
      booleanNumber('webhook_lock_traffic', item.content.webhookLocksTraffic),
      booleanNumber('ja4_tls_ch', item.content.ja4TlsClientHello),
      booleanNumber('ja4_tls_ch_ignore_sni', item.content.ja4TlsClientHelloIgnoresSni),
      booleanNumber('ja4_tls_sh', item.content.ja4TlsServerHello),
      booleanNumber('ja4_http', item.content.ja4Http),
      item.content.ruleCount, Number(item.content.sessionFilterConfigured),
      'payload capture', 'capture format', 'webhook', 'ja4', 'content rules',
    );
    if (item.ssh) values.push(
      scalar('hostkey_policy', item.ssh.hostKeyPolicy), Number(item.ssh.hostKeyConfigured),
      booleanNumber('shell', item.ssh.shell), booleanNumber('exec', item.ssh.exec),
      booleanNumber('subsystem', item.ssh.subsystem), booleanNumber('pty', item.ssh.pty),
      booleanNumber('environment', item.ssh.environment),
      booleanNumber('local_forward', item.ssh.localForward),
      booleanNumber('remote_forward', item.ssh.remoteForward),
      booleanNumber('x11', item.ssh.x11), booleanNumber('agent', item.ssh.agent),
      'host key', 'forwarding',
    );
    if (item.dns) values.push(
      booleanNumber('match_request_id', item.dns.matchRequestId),
      booleanNumber('randomize_id', item.dns.randomizeId),
      booleanNumber('cached_responses', item.dns.cachedResponses),
      'request id', 'randomize', 'cached responses',
    );
    if (item.script) {
      const type = scalar('type', item.script.runtime === 'python' ? '0' : item.script.runtime === 'go' ? '1' : '-1');
      values.push(type === '0' ? 'python' : type === '1' ? 'go' : 'unknown',
        Number(item.script.modulePathConfigured), 'runtime', 'module path');
    }
    if (item.authentication) values.push(
      booleanNumber('authenticate', item.authentication.authenticate),
      booleanNumber('resolve', item.authentication.resolve),
      item.authentication.identityCount, 'authenticate', 'resolve identities', 'identity mappings',
    );
    return values;
  }

  private systemSearchValues(settings: SystemSettings, debug: DebugSettings | null): ReadonlyArray<string | number> {
    const scalar = <T extends ConfigScalar>(path: string, fallback: T): T =>
      this.presentedValue(`settings.${path}`, fallback);
    const strings = (path: string, fallback: ReadonlyArray<string>): ReadonlyArray<string> =>
      this.presentedListValue(`settings.${path}`, fallback, 'string');
    const flag = (path: string, fallback: boolean): number => Number(scalar(path, fallback));
    const values: Array<string | number> = [
      'system', 'settings', 'traffic admission', 'workers', 'listener ports', 'logging', 'syslog',
      'http api', 'webhook', 'sift', 'socks', 'nameservers', 'performance tuning', 'debug logging',
      flag('accept_tproxy', settings.acceptTproxy),
      flag('accept_redirect', settings.acceptRedirect),
      flag('accept_socks', settings.acceptSocks),
      flag('accept_http_connect', settings.acceptHttpConnect),
      flag('accept_api', settings.acceptApi),
      flag('extended_local_destination_protection', settings.extendedLocalDestinationProtection),
      flag('policy_fail_open', settings.policyFailOpen),
      flag('policy_access_request_fail_open', settings.accessRequestFailOpen),
      scalar('plaintext_workers', settings.workers.plaintext),
      scalar('ssl_workers', settings.workers.tls),
      scalar('udp_workers', settings.workers.udp),
      scalar('dtls_workers', settings.workers.dtls),
      scalar('quic_workers', settings.workers.quic),
      scalar('socks_workers', settings.workers.socks),
      scalar('http_connect_workers', settings.workers.httpConnect),
      scalar('plaintext_port', settings.ports.plaintext),
      scalar('ssl_port', settings.ports.tls),
      scalar('udp_port', settings.ports.udp),
      scalar('dtls_port', settings.ports.dtls),
      scalar('quic_port', settings.ports.quic),
      scalar('socks_port', settings.ports.socks),
      scalar('http_connect_port', settings.ports.httpConnect),
      scalar('ssl_ocsp_status_ttl', settings.ocspStatusTtl),
      scalar('ssl_crl_status_ttl', settings.crlStatusTtl),
      flag('default_write_payload', settings.logging.defaultWritePayload),
      scalar('write_pcap_single_quota', settings.logging.pcapSingleQuota),
      scalar('log_level', settings.logging.level),
      flag('log_console', settings.logging.console),
      scalar('syslog_port', settings.logging.syslogPort),
      scalar('syslog_facility', settings.logging.syslogFacility),
      scalar('syslog_level', settings.logging.syslogLevel),
      scalar('syslog_family', settings.logging.syslogFamily),
      scalar('cli.port', settings.auxiliary.cliPort),
      flag('tpool_log', settings.auxiliary.threadPoolLogging),
      flag('socks.async_dns', settings.auxiliary.socksAsyncDns),
      flag('socks.ipver_mixing', settings.auxiliary.socksIpVersionMixing),
      flag('socks.prefer_ipv6', settings.auxiliary.socksPreferIpv6),
      ...strings('udp_quick_ports', settings.auxiliary.udpQuickPorts),
      scalar('tuning.host_bufsz_min', settings.auxiliary.tuning.hostBufferMin),
      scalar('tuning.host_bufsz_max_multiplier', settings.auxiliary.tuning.hostBufferMaxMultiplier),
      scalar('tuning.host_write_full', settings.auxiliary.tuning.hostWriteFull),
      scalar('tuning.host_io_batch', settings.auxiliary.tuning.hostIoBatch),
      scalar('tuning.tls_write_chunk', settings.auxiliary.tuning.tlsWriteChunk),
      scalar('tuning.host_open_timeout', settings.auxiliary.tuning.hostOpenTimeout),
      scalar('tuning.host_idle_timeout', settings.auxiliary.tuning.hostIdleTimeout),
      scalar('tuning.nbr_cache_size', settings.auxiliary.tuning.neighborCacheSize),
      flag('ssl_autodetect', settings.tlsAutodetect),
      flag('ssl_autodetect_harder', settings.tlsAutodetectHarder),
      flag('ssl_use_ktls', settings.kernelTls),
      ...strings('nameservers', settings.nameservers),
      scalar('http_api.key_timeout', settings.httpApi.keyTimeout),
      scalar('http_api.port', settings.httpApi.port),
      flag('http_api.key_extend_on_access', settings.httpApi.keyExtendOnAccess),
      flag('http_api.loopback_only', settings.httpApi.loopbackOnly),
      flag('http_api.pam_login', settings.httpApi.pamLogin),
      flag('http_api.allow_api_header', settings.httpApi.allowApiHeader),
      ...strings('http_api.allowed_ips', settings.httpApi.allowedIps),
      flag('webhook.enabled', settings.webhook.enabled),
      flag('webhook.tls_verify', settings.webhook.tlsVerify),
      flag('webhook.sift', settings.webhook.siftEnabled),
      flag('webhook.api_override', settings.webhook.apiOverride),
      scalar('webhook.sift_lored_mode', settings.webhook.siftLoredMode),
      flag('webhook.sift_lored_include_url', settings.webhook.siftLoredIncludeUrl),
      scalar('webhook.sift_payload_limit_per_direction', settings.webhook.siftPayloadLimitPerDirection),
      scalar('webhook.ping_interval', settings.webhook.pingInterval),
      scalar('webhook.nbr_update_interval', settings.webhook.neighborUpdateInterval),
      scalar('webhook.nbr_tag_refresh_age', settings.webhook.neighborTagRefreshAge),
      flag('webhook.task_debug', settings.webhook.taskDebug),
      flag('webhook.task_debug_dump', settings.webhook.taskDebugDump),
      Number(settings.logging.payloadDirectoryConfigured), Number(settings.logging.fileConfigured),
      Number(settings.logging.sslKeyFileConfigured), Number(settings.logging.syslogServerConfigured),
      Number(settings.auxiliary.certificatesPathConfigured),
      Number(settings.auxiliary.certificatePasswordConfigured),
      Number(settings.auxiliary.certificateTransparencyLogConfigured),
      Number(settings.auxiliary.caBundlePathConfigured), Number(settings.auxiliary.caBundleFileConfigured),
      Number(settings.auxiliary.messagesDirectoryConfigured), Number(settings.auxiliary.cliPasswordConfigured),
      Number(settings.auxiliary.webRatingKeyConfigured), Number(settings.auxiliary.adminGroupConfigured),
      Number(settings.httpApi.bindAddressConfigured), Number(settings.httpApi.bindInterfaceConfigured),
      Number(settings.webhook.urlConfigured), Number(settings.webhook.siftUrlConfigured),
      Number(settings.webhook.siftTenantConfigured), Number(settings.webhook.siftInstanceConfigured),
      Number(settings.webhook.hostIdConfigured), Number(settings.webhook.bindInterfaceConfigured),
    ];
    if (debug) {
      values.push(
        Number(this.presentedValue('debug.log_data_crc', debug.logDataCrc)),
        Number(this.presentedValue('debug.log_sockets', debug.logSockets)),
        Number(this.presentedValue('debug.log_online_cx_name', debug.logOnlineConnectionName)),
        Number(this.presentedValue('debug.log_srclines', debug.logSourceLines)),
        Number(this.presentedValue('debug.log_srclines_always', debug.logSourceLinesAlways)),
      );
      for (const override of debug.moduleOverrides) {
        const value = this.presentedValue(`debug.log.${override.name}`, override.value);
        values.push(override.name, typeof value === 'boolean' ? Number(value) : value);
      }
    }
    return values;
  }

  private captureSearchValues(captures: CaptureSettings): ReadonlyArray<string | number> {
    return [
      'capture', 'captures', 'local capture', 'remote capture', 'gre',
      Number(this.presentedValue('captures.local.enabled', captures.local.enabled)),
      this.presentedValue('captures.local.format', captures.local.format),
      this.presentedValue('captures.local.pcap_quota', captures.local.quotaMiB),
      Number(captures.local.directoryConfigured), Number(captures.local.filePrefixConfigured),
      Number(captures.local.fileSuffixConfigured),
      Number(this.presentedValue('captures.remote.enabled', captures.remote.enabled)),
      this.presentedValue('captures.remote.tun_type', captures.remote.tunnelType),
      this.presentedValue('captures.remote.gre_format', captures.remote.greFormat),
      this.presentedValue('captures.remote.tun_ttl', captures.remote.ttl),
      Number(captures.remote.destinationConfigured), Number(captures.remote.bindInterfaceConfigured),
      Number(this.presentedValue('captures.options.calculate_checksums', captures.calculateChecksums)),
      'format', 'quota', 'tunnel', 'ttl', 'checksums',
    ];
  }

  private renderSearchResults() {
    const query = this.searchQuery.trim().toLocaleLowerCase();
    if (!query || !this.snapshot) return html`<div class="empty-state"><h2>Search</h2><p>Enter a configuration name, type, value, or field.</p></div>`;
    const policies = this.snapshot.policies.map((item, index) => {
      const base = `policy.[${index}]`;
      const name = this.presentedValue(`${base}.name`, item.name);
      const action = this.presentedValue(`${base}.action`, item.action);
      const values: ReadonlyArray<string | number> = [
        name, action, this.presentedValue(`${base}.proto`, item.protocol),
        ...this.presentedListValue(`${base}.src`, item.sources.map(source => source.name), 'string'),
        ...this.presentedListValue(`${base}.sport`, item.sourcePorts, 'string'),
        ...this.presentedListValue(`${base}.dst`, item.destinations.map(destination => destination.name), 'string'),
        ...this.presentedListValue(`${base}.dport`, item.destinationPorts, 'string'),
        ...this.presentedListValue(`${base}.features`, item.features, 'string'),
        this.presentedValue(`${base}.nat`, item.nat),
        this.presentedValue(`${base}.routing`, item.routing),
        this.presentedValue(`${base}.tls_profile`, item.tlsProfile),
        this.presentedValue(`${base}.ssh_profile`, item.sshProfile),
        this.presentedValue(`${base}.detection_profile`, item.detectionProfile),
        this.presentedValue(`${base}.content_profile`, item.contentProfile),
        this.presentedValue(`${base}.auth_profile`, item.authProfile),
        this.presentedValue(`${base}.alg_dns_profile`, item.dnsProfile),
        this.presentedValue(`${base}.script_profile`, item.scriptProfile),
      ];
      return {item, name, action, matches: this.searchMatches(values, query)};
    }).filter(item => item.matches);
    const addresses = this.snapshot.addresses.map((item, index) => {
      const base = `address_objects.[${index}]`;
      const name = this.presentedValue(`${base}.name`, item.name);
      const type = this.presentedValue(`${base}.type`, item.type);
      const value = this.presentedValue(`${base}.value`, item.value);
      return {item, name, type, value, matches: this.searchMatches([name, type, value], query)};
    }).filter(item => item.matches);
    const ports = this.snapshot.ports.map((item, index) => {
      const base = `port_objects.[${index}]`;
      const name = this.presentedValue(`${base}.name`, item.name);
      const start = this.presentedValue(`${base}.start`, item.start);
      const end = this.presentedValue(`${base}.end`, item.end);
      return {item, name, start, end, matches: this.searchMatches([name, start, end], query)};
    }).filter(item => item.matches);
    const protocols = this.snapshot.protocols.map((item, index) => {
      const base = `proto_objects.[${index}]`;
      const name = this.presentedValue(`${base}.name`, item.name);
      const number = this.presentedValue(`${base}.id`, item.number);
      return {item, name, number, matches: this.searchMatches([name, number], query)};
    }).filter(item => item.matches);
    const profilePrefixes = this.profileOriginPrefixes();
    const profiles = this.snapshot.profiles.map(item => {
      const prefix = profilePrefixes.get(item.id);
      const name = prefix ? this.presentedValue(`${prefix}name`, item.name) : item.name;
      const details = this.profileSearchValues(item, prefix);
      return {item, name, matches: this.searchMatches(details, query)};
    }).filter(item => item.matches);
    const authorities = (this.snapshot.securityAssets?.certificateAuthorities ?? []).map((item, index) => {
      const name = this.presentedValue(`tls_ca.[${index}].name`, item.name);
      const detail = item.pathConfigured ? 'Path configured · redacted' : 'Path not configured';
      return {
        item, name, detail,
        matches: this.searchMatches([name, 'certificate authority', 'ca', detail], query),
      };
    }).filter(item => item.matches);
    const signatureIndexes = {starttls: 0, detection: 0};
    const signatures = (this.snapshot.securityAssets?.signatures ?? []).map(item => {
      const index = signatureIndexes[item.kind]++;
      const base = `${item.kind}_signatures.[${index}]`;
      const name = this.presentedValue(`${base}.name`, item.name);
      const category = this.presentedValue(`${base}.cat`, item.category);
      const side = this.presentedValue(`${base}.side`, item.side);
      const severity = this.presentedValue(`${base}.severity`, item.severity);
      const group = this.presentedValue(`${base}.group`, item.group);
      const enables = this.presentedValue(`${base}.enables`, item.enables);
      const engine = this.presentedValue(`${base}.engine`, item.engine);
      const values: Array<string | number> = [
        name, category, side, severity, group, enables, engine,
        item.kind, 'signature', item.flow.length,
      ];
      for (const [flowIndex, flow] of item.flow.entries()) {
        const flowBase = `${base}.flow.[${flowIndex}]`;
        values.push(
          this.presentedValue(`${flowBase}.side`, flow.side),
          this.presentedValue(`${flowBase}.type`, flow.type),
          this.presentedValue(`${flowBase}.bytes_start`, flow.bytesStart),
          this.presentedValue(`${flowBase}.bytes_max`, flow.bytesMax),
        );
      }
      return {
        item, name, detail: `${item.kind.toUpperCase()} · ${category || 'uncategorized'} · ${item.flow.length} flow`,
        matches: this.searchMatches(values, query),
      };
    }).filter(item => item.matches);
    const contentProfileIndexes = new Map(
      this.snapshot.profiles.filter(item => item.content !== null).map((item, index) => [item.id, index]),
    );
    const contentRules = this.snapshot.profiles.flatMap(profile => {
      if (!profile.content) return [];
      const profileIndex = contentProfileIndexes.get(profile.id) ?? -1;
      const profileName = profilePrefixes.get(profile.id)
        ? this.presentedValue(`${profilePrefixes.get(profile.id)!}name`, profile.name)
        : profile.name;
      return profile.content.rules.map((item, index) => {
        const base = `content_profiles.[${profileIndex}].content_rules.[${index}]`;
        const fillLength = this.presentedValue(`${base}.fill_length`, item.fillLength);
        const replaceEachNth = this.presentedValue(`${base}.replace_each_nth`, item.replaceEachNth);
        return {
          item,
          name: `${profileName} · rule ${index + 1}`,
          detail: `${item.replacementConfigured ? 'Replacement configured' : 'No replacement'} · every ${replaceEachNth}`,
          matches: this.searchMatches([
            profileName, 'content rule', index + 1, Number(fillLength), replaceEachNth,
            item.matchConfigured ? 'match configured' : 'match missing',
            item.replacementConfigured ? 'replacement configured' : 'no replacement',
          ], query),
        };
      });
    }).filter(item => item.matches);
    const settings = this.snapshot.settings;
    const systemMatches = settings
      ? this.searchMatches(this.systemSearchValues(settings, this.snapshot.debug), query)
      : false;
    const captures = this.snapshot.captures;
    const capturesMatch = captures
      ? this.searchMatches(this.captureSearchValues(captures), query)
      : false;
    const count = policies.length + addresses.length + ports.length + protocols.length + profiles.length +
      authorities.length + signatures.length + contentRules.length + Number(systemMatches) + Number(capturesMatch);
    const row = (kind: string, name: string, detail: string, open: (origin: HTMLElement) => void) => html`
      <button class="row object-row" type="button"
        @click=${(event: MouseEvent) => open(event.currentTarget as HTMLElement)}>
        <strong>${name}</strong><span class="action">${kind}</span><span class="object-value">${detail}</span><span>Open</span>
      </button>`;
    return html`
      <div class="content" tabindex="0">
        <div class="section-head"><div><h2>Search results</h2><p>${count} matches for “${this.searchQuery.trim()}”</p></div></div>
        ${count === 0 ? html`<div class="empty-state"><h2>No matches</h2><p>Try a name, type, value, action, or reference.</p></div>` : html`
          <div class="table" role="group" aria-label="Search results">
            <div class="row object-row heading" aria-hidden="true"><span>Name</span><span>Kind</span><span>Match context</span><span></span></div>
            ${policies.map(result => row('Policy', result.name, result.action, origin => this.openPolicy(result.item, origin)))}
            ${addresses.map(result => row('Address', result.name, `${result.type} · ${result.value}`, origin => this.openAddress(result.item.id, origin)))}
            ${ports.map(result => row('Port', result.name, result.start === result.end ? String(result.start) : `${result.start}–${result.end}`, origin => this.openPort(result.item.id, origin)))}
            ${protocols.map(result => row('Protocol', result.name, String(result.number), origin => this.openProtocol(result.item.id, origin)))}
            ${profiles.map(result => row('Profile', result.name, result.item.type, origin => this.openProfile(result.item.id, origin)))}
            ${contentRules.map(result => row('Content rule', result.name, result.detail, origin => this.openContentRule(result.item.id, origin)))}
            ${authorities.map(result => row('Certificate authority', result.name, result.detail, origin => this.openAuthority(result.item.id, origin)))}
            ${signatures.map(result => row('Signature', result.name, result.detail, origin => this.openSignature(result.item.id, origin)))}
            ${systemMatches ? row('System', 'System settings', 'Typed runtime configuration', origin => this.openSystemDrawer('settings', origin)) : nothing}
            ${capturesMatch ? row('Captures', 'Capture settings', 'Local and remote capture', origin => this.openSystemDrawer('captures', origin)) : nothing}
          </div>`}
      </div>`;
  }

  private referenceNameSummary(names: ReadonlyArray<string>): string {
    if (names.length === 0) return 'None';
    const [first, ...rest] = names;
    return `${first!}${rest.length > 0 ? ` +${rest.length}` : ''}`;
  }

  private renderObjects() {
    const overlayCounts = this.overlayCounts();
    const profilePrefixes = this.profileOriginPrefixes();
    return html`
      <div class="content" tabindex="0">
        <div class="section-head">
          <div><h2>Configuration objects</h2><p>Reusable values referenced by policy</p></div>
          <div class="structural-action object-structural-action">
            <div class="structural-buttons">
              <button class="primary" type="button" ?disabled=${!this.structuralDraftsAvailable}
                aria-describedby="new-object-blocker"
                @click=${(event: MouseEvent) => this.openNewAddress(event.currentTarget as HTMLElement)}>
                New address
              </button>
              <button class="primary" type="button" ?disabled=${!this.structuralDraftsAvailable}
                aria-describedby="new-object-blocker"
                @click=${(event: MouseEvent) => this.openNewPort(event.currentTarget as HTMLElement)}>
                New port
              </button>
              <button class="primary" type="button" ?disabled=${!this.structuralDraftsAvailable}
                aria-describedby="new-object-blocker"
                @click=${(event: MouseEvent) => this.openNewProtocol(event.currentTarget as HTMLElement)}>
                New protocol
              </button>
            </div>
            <small id="new-object-blocker">${this.structuralDraftsAvailable
              ? 'Creates one typed operation in the shared workspace draft.'
              : 'Requires reviewed structural transactions and stable entity IDs.'}</small>
          </div>
        </div>
        <section class="object-section">
          <h3>Address objects</h3>
          <div class="table" role="group" aria-label="Address objects">
            <div class="row object-row heading" aria-hidden="true">
              <span>Name</span><span>Type</span><span>Value</span><span>Uses</span>
            </div>
            ${this.snapshot?.addresses.map((address, index) => {
              const base = `address_objects.[${index}]`;
              return html`<button class="row object-row" type="button"
                @click=${(event: MouseEvent) => this.openAddress(address.id, event.currentTarget as HTMLElement)}>
                <strong>${this.presentedValue(`${base}.name`, address.name)}</strong>
                <span class="action">${this.presentedValue(`${base}.type`, address.type)}</span>
                <span class="object-value">${this.presentedValue(`${base}.value`, address.value)}</span>
                <span class="row-meta"><span>${address.usedBy.length}</span>${this.renderPendingBadge('address', address.id)}${this.renderOverlayBadge(`${base}.`, overlayCounts)}</span>
              </button>`;
            })}
          </div>
        </section>
        <section class="object-section">
          <h3>Port objects</h3>
          <div class="table" role="group" aria-label="Port objects">
            <div class="row object-row heading" aria-hidden="true">
              <span>Name</span><span>Type</span><span>Value</span><span>Uses</span>
            </div>
            ${this.snapshot?.ports.map((port, index) => {
              const base = `port_objects.[${index}]`;
              const start = this.presentedValue(`${base}.start`, port.start);
              const end = this.presentedValue(`${base}.end`, port.end);
              return html`<button class="row object-row" type="button"
                @click=${(event: MouseEvent) => this.openPort(port.id, event.currentTarget as HTMLElement)}>
                <strong>${this.presentedValue(`${base}.name`, port.name)}</strong><span>Port range</span>
                <span class="object-value">${start === end ? start : `${start}–${end}`}</span>
                <span class="row-meta"><span>${port.usedBy.length}</span>${this.renderPendingBadge('port', port.id)}${this.renderOverlayBadge(`${base}.`, overlayCounts)}</span>
              </button>`;
            })}
          </div>
        </section>
        <section class="object-section">
          <h3>Protocol objects</h3>
          <div class="table" role="group" aria-label="Protocol objects">
            <div class="row object-row heading" aria-hidden="true">
              <span>Name</span><span>Type</span><span>Value</span><span>Uses</span>
            </div>
            ${this.snapshot?.protocols.map((protocol, index) => {
              const base = `proto_objects.[${index}]`;
              return html`<button class="row object-row" type="button"
                @click=${(event: MouseEvent) => this.openProtocol(protocol.id, event.currentTarget as HTMLElement)}>
                <strong>${this.presentedValue(`${base}.name`, protocol.name)}</strong><span>IP protocol</span>
                <span class="object-value">${this.presentedValue(`${base}.id`, protocol.number)}</span>
                <span class="row-meta"><span>${protocol.usedBy.length}</span>${this.renderPendingBadge('protocol', protocol.id)}${this.renderOverlayBadge(`${base}.`, overlayCounts)}</span>
              </button>`;
            })}
          </div>
        </section>
        <section class="object-section">
          <h3>Profiles and routing</h3>
          <div class="table" role="group" aria-label="Profiles and routing">
            <div class="row object-row heading" aria-hidden="true">
              <span>Name</span><span>Type</span><span>Value exposure</span><span>Uses</span>
            </div>
            ${this.snapshot?.profiles.map(profile => {
              const prefix = profilePrefixes.get(profile.id);
              const name = prefix ? this.presentedValue(`${prefix}name`, profile.name) : profile.name;
              return html`<button class="row object-row" type="button"
                @click=${(event: MouseEvent) => this.openProfile(profile.id, event.currentTarget as HTMLElement)}>
                <strong>${name}</strong><span class="action">${profile.type}</span>
                <span class="row-meta"><span>${profile.routing || profile.tls || profile.detection || profile.content || profile.ssh ||
                  profile.dns || profile.script || profile.authentication
                  ? 'Typed details' : 'Metadata only'}</span>${this.renderPendingBadge('profile', profile.id)}${this.renderOverlayBadge(prefix, overlayCounts)}</span>
                <span>${profile.usedBy.length}</span>
              </button>`;
            })}
          </div>
        </section>
      </div>
    `;
  }

  private renderNetwork() {
    const metrics = this.runtimeMetrics;
    const presentation = this.collectorPresentation(
      metrics.state, metrics.lastSuccessAtUnixMs, 5_000,
    );
    return html`
      <div class="content dashboard" tabindex="0">
        <div class="section-head">
          <div><h2>Listener workload</h2><p>Runtime view of Smithproxy network entry points</p></div>
        </div>
        ${this.renderInterfaceSummary()}
        ${this.renderNeighborSummary()}
        ${this.renderCollectorNotice(presentation, metrics.detail, metrics.lastSuccessAtUnixMs)}
        <div class="card-grid" aria-label="Network listeners">
          ${metrics.listeners.map(listener => {
            const listenerActive = presentation.current && listener.workers > 0;
            const listenerState = !presentation.current ? 'Last known' : listenerActive ? 'Running' : 'Idle';
            return html`
              <article class="domain-card">
                <header>
                  <div><h3>${listener.name}</h3><p>${listener.workers} worker${listener.workers === 1 ? '' : 's'}</p></div>
                  <span class="status ${listenerActive ? '' : 'disabled'}">${listenerState}</span>
                </header>
                <dl>
                  <dt>Active sessions</dt><dd>${listener.sessionsActive.toLocaleString()}</dd>
                  <dt>Total sessions</dt><dd>${listener.sessionsTotal.toLocaleString()}</dd>
                  <dt>Traffic up</dt><dd>${this.formatBytes(listener.bytesUp)}</dd>
                  <dt>Traffic down</dt><dd>${this.formatBytes(listener.bytesDown)}</dd>
                </dl>
              </article>`;
          })}
          ${metrics.listeners.length === 0 ? html`<div class="metrics-message">No listener samples are available yet.</div>` : nothing}
        </div>
      </div>
    `;
  }

  private renderNeighborSummary() {
    const neighbors = this.neighbors;
    const presentation = this.collectorPresentation(
      neighbors.state, neighbors.lastSuccessAtUnixMs, 30_000,
    );
    return html`
      <section class="runtime-summary" aria-label="Neighborhood activity">
        <div class="runtime-heading">
          <div><h3>Neighborhood activity</h3><p>Privacy-safe aggregates for recently observed endpoints</p></div>
          <span class="runtime-state ${presentation.tone}"
            title=${neighbors.detail}>● ${presentation.label}</span>
        </div>
        <div class="metric-grid">
          <article class="metric">
            <span class="metric-label">Known endpoints</span>
            <strong class="metric-value">${neighbors.hostsTotal.toLocaleString()}</strong>
            <span class="metric-note">Seen during the 30-day aggregation window</span>
          </article>
          <article class="metric">
            <span class="metric-label">Active today</span>
            <strong class="metric-value">${neighbors.activeToday.toLocaleString()}</strong>
            <span class="metric-note">${neighbors.activeWeek.toLocaleString()} active this week</span>
          </article>
          <article class="metric">
            <span class="metric-label">Observations</span>
            <strong class="metric-value">${neighbors.observations.toLocaleString()}</strong>
            <span class="metric-note">${neighbors.taggedHosts.toLocaleString()} endpoints carry tags</span>
          </article>
          <article class="metric">
            <span class="metric-label">Observed traffic</span>
            <strong class="metric-value">${this.formatBytes(neighbors.bytesUp + neighbors.bytesDown)}</strong>
            <span class="metric-note">Last success: ${this.timeLabel(neighbors.lastSuccessAtUnixMs)}</span>
          </article>
        </div>
        ${this.renderCollectorNotice(presentation, neighbors.detail, neighbors.lastSuccessAtUnixMs)}
        <div class="privacy-note">Hostnames, tags, labels, and per-endpoint timelines remain inside the GUI core.</div>
      </section>
    `;
  }

  private renderInterfaceSummary() {
    const interfaces = this.interfaces;
    const presentation = this.collectorPresentation(
      interfaces.state, interfaces.lastSuccessAtUnixMs, 30_000,
    );
    return html`
      <section class="runtime-summary" aria-label="Interface synchronization">
        <div class="runtime-heading">
          <div><h3>Interface synchronization</h3><p>Privacy-safe netlink monitor health and inventory totals</p></div>
          <span class="runtime-state ${presentation.tone}"
            title=${interfaces.detail}>● ${presentation.label}</span>
        </div>
        <div class="metric-grid">
          <article class="metric">
            <span class="metric-label">Interfaces</span>
            <strong class="metric-value">${interfaces.interfaces.toLocaleString()}</strong>
            <span class="metric-note">Generation ${interfaces.generation.toLocaleString()}</span>
          </article>
          <article class="metric">
            <span class="metric-label">Addresses</span>
            <strong class="metric-value">${interfaces.addresses.toLocaleString()}</strong>
            <span class="metric-note">${interfaces.ipv4Addresses.toLocaleString()} IPv4 · ${interfaces.ipv6Addresses.toLocaleString()} IPv6</span>
          </article>
          <article class="metric">
            <span class="metric-label">Synchronizations</span>
            <strong class="metric-value">${interfaces.synchronizationSuccesses.toLocaleString()}</strong>
            <span class="metric-note">${interfaces.synchronizationAttempts.toLocaleString()} attempts · ${interfaces.synchronizationErrors.toLocaleString()} errors</span>
          </article>
          <article class="metric">
            <span class="metric-label">Changed events</span>
            <strong class="metric-value">${interfaces.changedEventDatagrams.toLocaleString()}</strong>
            <span class="metric-note">${interfaces.eventDatagrams.toLocaleString()} event datagrams · ${interfaces.synchronizationRunning ? 'sync running' : 'sync idle'}</span>
          </article>
        </div>
        ${interfaces.lastErrorCode === null ? nothing : html`
          <div class="metrics-message" role="status">Stable diagnostic code: ${interfaces.lastErrorCode}</div>`}
        ${this.renderCollectorNotice(presentation, interfaces.detail, interfaces.lastSuccessAtUnixMs)}
        <div class="privacy-note">Interface names, indexes, addresses, routes, namespaces, and raw kernel errors never cross the GUI core boundary.</div>
      </section>
    `;
  }

  private availabilityLabel(): string {
    if (this.systemStatus.availabilitySamples === 0) return 'No samples';
    const ratio = this.systemStatus.availabilitySuccessful / this.systemStatus.availabilitySamples;
    return `${(ratio * 100).toFixed(ratio === 1 ? 0 : 1)}%`;
  }

  private sampleAgeLabel(value: number | null): string {
    if (value === null) return 'Never sampled';
    const seconds = Math.max(0, Math.floor((Date.now() - value) / 1000));
    if (seconds < 2) return 'Now';
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    return minutes < 60 ? `${minutes}m ago` : `${Math.floor(minutes / 60)}h ago`;
  }

  private freshnessTone(state: FreshnessState): 'success' | 'warning' | 'danger' {
    if (state === 'fresh') return 'success';
    if (state === 'stale') return 'danger';
    return 'warning';
  }

  private collectorPresentation(
    state: string,
    lastSuccessAtUnixMs: number | null,
    expectedIntervalMs: number,
    knownFreshness?: FreshnessState,
  ): CollectorPresentation {
    const freshness = knownFreshness ?? classifyFreshness(lastSuccessAtUnixMs, expectedIntervalMs).state;
    const ready = state === 'ready';
    const tone: StatusTone = !ready
      ? state === 'unavailable' ? 'danger' : 'warning'
      : this.freshnessTone(freshness);
    return {
      label: ready
        ? `${displayState(state)} · ${freshnessLabel(freshness)}`
        : `${displayState(state)} · Last data ${freshnessLabel(freshness).toLocaleLowerCase()}`,
      tone,
      current: ready && freshness === 'fresh',
      reportedReady: ready,
    };
  }

  private renderCollectorNotice(
    presentation: CollectorPresentation,
    detail: string,
    lastSuccessAtUnixMs: number | null,
  ) {
    if (presentation.current) return nothing;
    const reason = presentation.reportedReady ? 'Collector updates are delayed.' : detail;
    const dataStatus = lastSuccessAtUnixMs === null
      ? 'No successful aggregate sample is available; values are not current.'
      : `Displaying the last successful aggregate sample from ${this.timeLabel(lastSuccessAtUnixMs)}; values are not current.`;
    return html`<div class="metrics-message" role="status">
      ${reason} ${dataStatus}
    </div>`;
  }

  private renderOperationalHealth() {
    const items = [
      {name: 'Control plane', state: this.systemStatus.smithproxy, checked: this.systemStatus.checkedAtUnixMs,
        lastSuccess: this.systemStatus.lastSuccessAtUnixMs, intervalMs: 5_000},
      {name: 'Listener metrics', state: this.runtimeMetrics.state, checked: this.runtimeMetrics.checkedAtUnixMs,
        lastSuccess: this.runtimeMetrics.lastSuccessAtUnixMs, intervalMs: 5_000},
      {name: 'Session activity', state: this.sessionActivity.state, checked: this.sessionActivity.checkedAtUnixMs,
        lastSuccess: this.sessionActivity.lastSuccessAtUnixMs, intervalMs: 10_000},
      {name: 'TLS cache', state: this.tlsCache.state, checked: this.tlsCache.checkedAtUnixMs,
        lastSuccess: this.tlsCache.lastSuccessAtUnixMs, intervalMs: 5_000},
      {name: 'Neighborhood', state: this.neighbors.state, checked: this.neighbors.checkedAtUnixMs,
        lastSuccess: this.neighbors.lastSuccessAtUnixMs, intervalMs: 30_000},
      {name: 'Interfaces', state: this.interfaces.state, checked: this.interfaces.checkedAtUnixMs,
        lastSuccess: this.interfaces.lastSuccessAtUnixMs, intervalMs: 30_000},
      {name: 'Configuration', state: this.snapshot?.state ?? 'starting', checked: this.snapshot?.checkedAtUnixMs ?? null,
        lastSuccess: this.snapshot?.lastSuccessAtUnixMs ?? null, intervalMs: 30_000},
    ];
    return html`
      <section class="runtime-summary" aria-label="Operational health matrix">
        <div class="runtime-heading">
          <div><h3>Operational health</h3><p>Current state and freshness across GUI core data planes</p></div>
        </div>
        <div class="card-grid">
          ${items.map(item => {
            const freshness = classifyFreshness(item.lastSuccess, item.intervalMs);
            const stateTone = item.state === 'ready' ? this.freshnessTone(freshness.state) :
              ['unreachable', 'unauthorized', 'error', 'unavailable'].includes(item.state) ? 'danger' : 'warning';
            return html`<article class="domain-card">
              <header><div><h3>${item.name}</h3>
                <p>Last success: ${this.sampleAgeLabel(item.lastSuccess)} · checked ${this.sampleAgeLabel(item.checked)}</p></div>
                <span class="runtime-state ${stateTone}">
                  ● ${displayState(item.state)} · ${freshnessLabel(freshness.state)}
                </span>
              </header>
            </article>`;
          })}
        </div>
      </section>`;
  }

  private renderProbeAnalysis() {
    const history = this.systemStatus.history;
    const latencies = history.flatMap(sample => sample.state === 'ready' && sample.latencyMs !== null
      ? [sample.latencyMs] : []).sort((left, right) => left - right);
    const percentile = (fraction: number): string => {
      if (latencies.length === 0) return '—';
      const index = Math.min(latencies.length - 1, Math.max(0, Math.ceil(latencies.length * fraction) - 1));
      return `${latencies[index]} ms`;
    };
    const incidents = history.filter(sample => sample.state !== 'ready').length;
    return html`
      <div class="metric-grid" aria-label="Probe latency analysis">
        <article class="metric"><span class="metric-label">Median latency</span>
          <strong class="metric-value">${percentile(.5)}</strong><span class="metric-note">p50 successful probes</span></article>
        <article class="metric"><span class="metric-label">Tail latency</span>
          <strong class="metric-value">${percentile(.95)}</strong><span class="metric-note">p95 successful probes</span></article>
        <article class="metric"><span class="metric-label">Maximum latency</span>
          <strong class="metric-value">${latencies.length ? `${latencies.at(-1)} ms` : '—'}</strong>
          <span class="metric-note">Successful probes in window</span></article>
        <article class="metric"><span class="metric-label">Incident samples</span>
          <strong class="metric-value ${incidents ? 'danger' : ''}">${incidents}</strong>
          <span class="metric-note">Non-ready states in window</span></article>
      </div>`;
  }

  private durationLabel(milliseconds: number): string {
    const seconds = Math.max(0, Math.round(milliseconds / 1000));
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    const remainder = seconds % 60;
    return minutes < 60 ? `${minutes}m ${remainder}s` : `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
  }

  private renderProbeIncidents() {
    const incidents = [...probeIncidents(this.systemStatus.history)].reverse().slice(0, 5);
    const active = incidents.filter(incident => incident.recoveredAtUnixMs === null).length;
    return html`
      <section class="monitor-panel" aria-label="Control-plane incident timeline">
        <div class="runtime-heading">
          <div><h3>Observed incidents</h3><p>Consecutive non-ready probes grouped into recovery windows</p></div>
          <span class="runtime-state ${active ? 'danger' : 'success'}">
            ${active ? `${active} active` : incidents.length ? '● Recovered' : '● Clear'}
          </span>
        </div>
        ${incidents.length === 0 ? html`
          <div class="privacy-note">No control-plane incident was observed in the current five-minute window.</div>
        ` : html`
          <div class="incident-list" role="list">
            ${incidents.map(incident => {
              const end = incident.recoveredAtUnixMs ?? incident.lastFailureAtUnixMs;
              return html`
                <article class="incident-row ${incident.recoveredAtUnixMs === null ? 'active' : ''}" role="listitem">
                  <span class="incident-time">${this.timeLabel(incident.startedAtUnixMs)}</span>
                  <span class="incident-state">
                    <strong>${incident.recoveredAtUnixMs === null ? 'Incident active' : 'Recovered'}</strong>
                    <small>${incident.states.map(displayState).join(' → ')}</small>
                  </span>
                  <span>${incident.samples} failed probe${incident.samples === 1 ? '' : 's'}</span>
                  <span class="incident-duration">${incident.recoveredAtUnixMs === null ? 'observed ' : 'after '}${this.durationLabel(end - incident.startedAtUnixMs)}</span>
                </article>`;
            })}
          </div>
        `}
      </section>`;
  }

  private renderActiveAlerts() {
    const alerts = this.operationalAlerts.alerts;
    return html`
      <section class="monitor-panel" aria-label="Active operational alerts">
        <div class="runtime-heading">
          <div><h3>Active alerts</h3><p>Locally derived health, freshness, availability, and capacity conditions</p></div>
          <span class="runtime-state ${this.alertsError || alerts.some(item => item.severity === 'critical')
            ? 'danger' : alerts.length ? 'warning' : 'success'}">
            ${this.alertsError ? 'Unavailable' : alerts.length === 0 ? '● Clear' : `${alerts.length} active`}
          </span>
        </div>
        ${this.alertsError ? html`<div class="metrics-message">${this.alertsError}</div>` : alerts.length === 0 ? html`
          <div class="privacy-note">No active alert condition was detected by the GUI core.</div>
        ` : html`
          <div class="alert-list" role="list">
            ${alerts.map(alert => html`
              <article class="alert-row ${alert.severity}" role="listitem">
                <span class="event-severity ${alert.severity}">${alert.severity}</span>
                <div><strong>${alert.title}</strong><p>${alert.detail}</p></div>
              </article>
            `)}
          </div>
        `}
      </section>`;
  }

  private timeLabel(value: number | null): string {
    return value === null ? 'Never' : new Date(value).toLocaleString();
  }

  private uptimeLabel(): string {
    const milliseconds = this.systemStatus.uptimeMs;
    if (milliseconds === null) return 'Unknown';
    const seconds = Math.floor(milliseconds / 1000);
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m ${seconds % 60}s`;
  }

  private formatBytes(value: number): string {
    if (value < 1000) return `${value} B`;
    const units = ['kB', 'MB', 'GB', 'TB', 'PB'];
    let amount = value;
    let unit = -1;
    do {
      amount /= 1000;
      unit += 1;
    } while (amount >= 1000 && unit < units.length - 1);
    return `${amount.toFixed(amount >= 100 ? 0 : amount >= 10 ? 1 : 2)} ${units[unit]}`;
  }

  private renderRuntimeSummary() {
    const metrics = this.runtimeMetrics;
    const presentation = this.collectorPresentation(
      metrics.state, metrics.lastSuccessAtUnixMs, 5_000,
    );
    return html`
      <section class="runtime-summary" aria-label="Runtime metrics summary">
        <div class="runtime-heading">
          <div><h3>Runtime traffic</h3><p>Aggregated counters reported by Smithproxy listeners</p></div>
          <span class="runtime-state ${presentation.tone}" title=${metrics.detail}>
            ● ${presentation.label}
          </span>
        </div>
        <div class="metric-grid">
          <article class="metric">
            <span class="metric-label">Active sessions</span>
            <strong class="metric-value">${metrics.totals.sessionsActive.toLocaleString()}</strong>
            <span class="metric-note">Across ${metrics.listeners.length} listener types</span>
          </article>
          <article class="metric">
            <span class="metric-label">Total sessions</span>
            <strong class="metric-value">${metrics.totals.sessionsTotal.toLocaleString()}</strong>
            <span class="metric-note">Since Smithproxy started</span>
          </article>
          <article class="metric">
            <span class="metric-label">Traffic processed</span>
            <strong class="metric-value">${this.formatBytes(metrics.totals.bytesUp + metrics.totals.bytesDown)}</strong>
            <span class="metric-note">${this.formatBytes(metrics.totals.bytesUp)} up · ${this.formatBytes(metrics.totals.bytesDown)} down</span>
          </article>
          <article class="metric">
            <span class="metric-label">Listener workers</span>
            <strong class="metric-value">${metrics.totals.workers.toLocaleString()}</strong>
            <span class="metric-note">Last success: ${this.timeLabel(metrics.lastSuccessAtUnixMs)}</span>
          </article>
        </div>
        ${this.renderCollectorNotice(presentation, metrics.detail, metrics.lastSuccessAtUnixMs)}
      </section>
    `;
  }

  private renderRuntimeHistory() {
    const history = this.runtimeMetrics.history;
    const emptySlots = Math.max(0, 60 - history.length);
    const sessionPeak = Math.max(0, ...history.map(sample => sample.sessionsActive));
    const rates = history.map((sample, index) => {
      const previous = index > 0 ? history[index - 1] : undefined;
      if (!previous || sample.state !== 'ready' || previous.state !== 'ready') return null;
      const elapsed = (sample.checkedAtUnixMs - previous.checkedAtUnixMs) / 1000;
      const currentBytes = sample.bytesUp + sample.bytesDown;
      const previousBytes = previous.bytesUp + previous.bytesDown;
      return elapsed > 0 && currentBytes >= previousBytes ? (currentBytes - previousBytes) / elapsed : null;
    });
    const validRates = rates.flatMap(rate => rate === null ? [] : [rate]);
    const throughputPeak = Math.max(0, ...validRates);
    const latestRate = validRates.at(-1) ?? 0;
    const readySamples = history.filter(sample => sample.state === 'ready').length;
    const sessionHeight = (value: number) => sessionPeak === 0 ? 0 : value / sessionPeak * 100;
    const trafficHeight = (value: number) => throughputPeak === 0 ? 0 : value / throughputPeak * 100;
    return html`
      <section class="monitor-panel" aria-label="Runtime history">
        <div class="runtime-heading">
          <div><h3>Five-minute runtime history</h3><p>Sixty bounded aggregate samples at the control-plane interval</p></div>
          <span class="runtime-state ${readySamples === history.length && history.length > 0 ? 'success' : 'warning'}">
            ${readySamples}/${history.length} ready
          </span>
        </div>
        <div class="trend-grid">
          <div class="trend-chart" role="img"
            aria-label="Active session trend. Peak ${sessionPeak} sessions across ${history.length} samples.">
            <header><strong>Active sessions</strong><span>peak ${sessionPeak.toLocaleString()}</span></header>
            <div class="trend-bars">
              ${Array.from({length: emptySlots}, () => html`<span class="trend-bar empty" aria-hidden="true"></span>`)}
              ${history.map(sample => html`<span
                class="trend-bar ${sample.state === 'ready' ? '' : 'unavailable'}"
                style=${`--bar-height:${sessionHeight(sample.sessionsActive).toFixed(2)}%`}
                title="${sample.sessionsActive} sessions · ${displayState(sample.state)} · ${this.timeLabel(sample.checkedAtUnixMs)}"
                aria-hidden="true"></span>`)}
            </div>
          </div>
          <div class="trend-chart" role="img"
            aria-label="Aggregate throughput trend. Peak ${this.formatBytes(throughputPeak)} per second.">
            <header><strong>Processed throughput</strong><span>${this.formatBytes(latestRate)}/s now</span></header>
            <div class="trend-bars">
              ${Array.from({length: emptySlots}, () => html`<span class="trend-bar empty" aria-hidden="true"></span>`)}
              ${history.map((sample, index) => {
                const rate = rates[index] ?? null;
                const unavailable = sample.state !== 'ready';
                return html`<span class="trend-bar traffic ${unavailable ? 'unavailable' : rate === null ? 'empty' : ''}"
                  style=${`--bar-height:${trafficHeight(rate ?? 0).toFixed(2)}%`}
                  title="${rate === null ? 'No rate' : `${this.formatBytes(rate)}/s`} · ${displayState(sample.state)} · ${this.timeLabel(sample.checkedAtUnixMs)}"
                  aria-hidden="true"></span>`;
              })}
            </div>
          </div>
        </div>
        <div class="privacy-note">
          History contains aggregate counters only; it carries no endpoints, session identifiers, or policy names.
        </div>
      </section>
    `;
  }

  private renderTlsCache() {
    const cache = this.tlsCache;
    const presentation = this.collectorPresentation(
      cache.state, cache.lastSuccessAtUnixMs, 5_000,
    );
    const utilization = cache.capacity === 0 ? 0 : Math.min(100, cache.size / cache.capacity * 100);
    return html`
      <section class="runtime-summary" aria-label="TLS interception cache">
        <div class="runtime-heading">
          <div><h3>TLS interception cache</h3><p>Aggregate certificate cache health without domain disclosure</p></div>
          <span class="runtime-state ${presentation.tone}"
            title=${cache.detail}>● ${presentation.label}</span>
        </div>
        <div class="metric-grid">
          <article class="metric">
            <span class="metric-label">Cached certificates</span>
            <strong class="metric-value">${cache.size.toLocaleString()}</strong>
            <span class="metric-note">Generated interception certificate entries</span>
          </article>
          <article class="metric">
            <span class="metric-label">Cache capacity</span>
            <strong class="metric-value">${cache.capacity.toLocaleString()}</strong>
            <span class="metric-note">Configured maximum entries</span>
          </article>
          <article class="metric">
            <span class="metric-label">Utilization</span>
            <strong class="metric-value">${utilization.toFixed(utilization === 0 ? 0 : 1)}%</strong>
            <div class="capacity-track" role="progressbar" aria-label="TLS cache utilization"
              aria-valuemin="0" aria-valuemax="100" aria-valuenow=${utilization.toFixed(1)}>
              <div class="capacity-fill" style=${`width: ${utilization}%`}></div>
            </div>
          </article>
          <article class="metric">
            <span class="metric-label">Last successful sample</span>
            <strong class="metric-value">${this.timeLabel(cache.lastSuccessAtUnixMs)}</strong>
            <span class="metric-note">${cache.detail}</span>
          </article>
        </div>
        ${this.renderCollectorNotice(presentation, cache.detail, cache.lastSuccessAtUnixMs)}
      </section>
    `;
  }

  private renderDashboard() {
    const history = this.systemStatus.history;
    const emptySlots = Math.max(0, 60 - history.length);
    return html`
      <div class="content dashboard" tabindex="0">
        <div class="section-head">
          <div><h2>Control plane</h2><p>Live reachability of the Smithproxy API</p></div>
        </div>
        <div class="metric-grid">
          <article class="metric">
            <span class="metric-label">Smithproxy API</span>
            <strong class="metric-value ${statusTone(this.systemStatus)}">${displayState(this.systemStatus.smithproxy)}</strong>
            <span class="metric-note">${this.systemStatus.detail}</span>
          </article>
          <article class="metric">
            <span class="metric-label">Probe latency</span>
            <strong class="metric-value">${this.systemStatus.latencyMs === null ? '—' : `${this.systemStatus.latencyMs} ms`}</strong>
            <span class="metric-note">Last API ping round trip</span>
          </article>
          <article class="metric">
            <span class="metric-label">Window availability</span>
            <strong class="metric-value">${this.availabilityLabel()}</strong>
            <span class="metric-note">${this.systemStatus.availabilitySuccessful} / ${this.systemStatus.availabilitySamples} successful probes</span>
          </article>
          <article class="metric">
            <span class="metric-label">GUI core uptime</span>
            <strong class="metric-value">${this.uptimeLabel()}</strong>
            <span class="metric-note">${this.systemStatus.totalProbes} probes · ${this.systemStatus.consecutiveFailures} consecutive failures</span>
          </article>
        </div>
        ${this.renderOperationalHealth()}
        ${this.renderActiveAlerts()}
        ${this.renderRuntimeSummary()}
        ${this.renderTlsCache()}
        <section class="monitor-panel" aria-label="Probe history">
          <h3>Recent probe history</h3>
          <p>Up to five minutes at the current five-second sampling interval. Last success: ${this.timeLabel(this.systemStatus.lastSuccessAtUnixMs)}.</p>
          <div class="probe-history" role="img" aria-label="${history.length} probe samples">
            ${Array.from({length: emptySlots}, () => html`<span class="probe" aria-hidden="true"></span>`)}
            ${history.map(sample => html`
              <span class="probe ${sample.state}" title="${displayState(sample.state)} · ${sample.latencyMs ?? '—'} ms · ${this.timeLabel(sample.checkedAtUnixMs)}" aria-hidden="true"></span>
            `)}
          </div>
          ${this.renderProbeAnalysis()}
        </section>
        ${this.renderProbeIncidents()}
        <div class="scope-note">
          Control-plane health and listener counters are live. TLS inspection outcomes and deeper dataplane health will be added as dedicated monitoring surfaces.
        </div>
      </div>
    `;
  }

  private renderCollectorMatrix() {
    const collectors = [
      {
        name: 'Runtime metrics', state: this.runtimeMetrics.state,
        lastSuccessAtUnixMs: this.runtimeMetrics.lastSuccessAtUnixMs,
        expectedIntervalMs: 5_000, detail: this.runtimeMetrics.detail,
      },
      {
        name: 'Session activity', state: this.sessionActivity.state,
        lastSuccessAtUnixMs: this.sessionActivity.lastSuccessAtUnixMs,
        expectedIntervalMs: 10_000, detail: this.sessionActivity.detail,
      },
      {
        name: 'TLS cache', state: this.tlsCache.state,
        lastSuccessAtUnixMs: this.tlsCache.lastSuccessAtUnixMs,
        expectedIntervalMs: 5_000, detail: this.tlsCache.detail,
      },
      {
        name: 'Network neighbors', state: this.neighbors.state,
        lastSuccessAtUnixMs: this.neighbors.lastSuccessAtUnixMs,
        expectedIntervalMs: 30_000, detail: this.neighbors.detail,
      },
      {
        name: 'Network interfaces', state: this.interfaces.state,
        lastSuccessAtUnixMs: this.interfaces.lastSuccessAtUnixMs,
        expectedIntervalMs: 30_000, detail: this.interfaces.detail,
      },
    ].map(item => {
      const freshness = classifyFreshness(
        item.lastSuccessAtUnixMs, item.expectedIntervalMs,
      ).state;
      return {
        ...item,
        freshness,
        presentation: this.collectorPresentation(
          item.state, item.lastSuccessAtUnixMs, item.expectedIntervalMs, freshness,
        ),
      };
    });
    return html`
      <section class="monitor-panel" aria-label="Collector health matrix">
        <div class="runtime-heading">
          <div><h3>Collector health matrix</h3><p>Reported state and interval-aware data freshness</p></div>
          <span class="runtime-state">${collectors.filter(item =>
            item.presentation.current).length}/${collectors.length} current</span>
        </div>
        <div class="table collector-table" tabindex="0" aria-label="Scrollable collector health table">
          <table class="listener-table" aria-label="Collector health">
            <thead><tr>
              <th>Collector</th><th>Reported state</th><th>Data freshness</th>
              <th>Expected cadence</th><th>Last success</th>
            </tr></thead>
            <tbody>
              ${collectors.map(item => {
                return html`<tr>
                  <td class="listener-name">${item.name}</td>
                  <td><span class="runtime-state ${item.presentation.tone}" title=${item.detail}>
                    ● ${displayState(item.state)}
                  </span></td>
                  <td><span class="runtime-state ${this.freshnessTone(item.freshness)}">
                    ● ${freshnessLabel(item.freshness)}
                  </span></td>
                  <td>${item.expectedIntervalMs / 1_000}s</td>
                  <td title=${this.timeLabel(item.lastSuccessAtUnixMs)}>
                    ${this.sampleAgeLabel(item.lastSuccessAtUnixMs)}
                  </td>
                </tr>`;
              })}
            </tbody>
          </table>
        </div>
      </section>`;
  }

  private renderEventStreamHealth() {
    const tone = this.eventStreamState === 'live' ? 'success' :
      this.eventStreamState === 'invalid' || this.eventStreamError ? 'danger' : 'warning';
    const recoveryLabel = !this.eventsAvailable ? 'Not advertised' :
      this.eventsError ? 'Unavailable' : 'Available';
    return html`
      <section class="monitor-panel" aria-label="Operational event transport">
        <div class="runtime-heading">
          <div>
            <h3>Operational event transport</h3>
            <p>Authenticated same-origin SSE with a bounded REST recovery snapshot</p>
          </div>
          <div class="preflight-actions">
            <span class="runtime-state ${tone}">● ${displayState(this.eventStreamState)}</span>
            ${this.eventStreamState === 'invalid' ? html`
              <button class="secondary" type="button" @click=${() => this.retryEventStream()}>
                Retry stream
              </button>
            ` : nothing}
          </div>
        </div>
        <div class="metric-grid">
          <article class="metric">
            <span class="metric-label">Last connection</span>
            <strong class="metric-value">${this.timeLabel(this.eventStreamConnectedAtUnixMs)}</strong>
            <span class="metric-note">Browser EventSource opened</span>
          </article>
          <article class="metric">
            <span class="metric-label">Last validated payload</span>
            <strong class="metric-value">${this.timeLabel(this.eventStreamLastMessageAtUnixMs)}</strong>
            <span class="metric-note">Snapshot or structured event accepted</span>
          </article>
          <article class="metric">
            <span class="metric-label">Reconnect attempts</span>
            <strong class="metric-value">${this.eventStreamReconnectCount.toLocaleString()}</strong>
            <span class="metric-note">Last interruption: ${this.timeLabel(this.eventStreamLastDisconnectAtUnixMs)}</span>
          </article>
          <article class="metric">
            <span class="metric-label">Recovery snapshot</span>
            <strong class="metric-value ${this.eventsError ? 'danger' : ''}">
              ${recoveryLabel}
            </strong>
            <span class="metric-note">${this.operationalEvents.events.length} bounded events retained</span>
          </article>
        </div>
        ${this.eventStreamError ? html`<div class="metrics-message" role="status">${this.eventStreamError}</div>` : nothing}
        <div class="privacy-note">
          ${this.operationalEvents.smithproxyEventsAvailable
            ? 'The feed includes reviewed Smithproxy events.'
            : 'The feed currently contains GUI-core control-plane and backend-job transitions only.'}
          Event payloads are validated before they update this state.
        </div>
      </section>
    `;
  }

  private renderMonitoring() {
    const metrics = this.runtimeMetrics;
    return html`
      <div class="content dashboard" tabindex="0">
        <div class="section-head">
          <div><h2>Listener monitoring</h2><p>Live aggregate counters from the Smithproxy runtime</p></div>
        </div>
        ${this.renderActiveAlerts()}
        ${this.renderEventStreamHealth()}
        ${this.renderCollectorMatrix()}
        ${this.renderProbeAnalysis()}
        ${this.renderProbeIncidents()}
        ${this.renderRuntimeSummary()}
        ${this.renderRuntimeHistory()}
        ${this.renderTlsCache()}
        ${this.renderSessionActivity()}
        <div class="table">
          <table class="listener-table">
            <thead><tr><th>Listener</th><th>Workers</th><th>Active</th><th>Total</th><th>Up</th><th>Down</th></tr></thead>
            <tbody>
              ${metrics.listeners.map(listener => html`
                <tr>
                  <td class="listener-name">${listener.name}</td>
                  <td>${listener.workers.toLocaleString()}</td>
                  <td>${listener.sessionsActive.toLocaleString()}</td>
                  <td>${listener.sessionsTotal.toLocaleString()}</td>
                  <td>${this.formatBytes(listener.bytesUp)}</td>
                  <td>${this.formatBytes(listener.bytesDown)}</td>
                </tr>
              `)}
              ${metrics.listeners.length === 0 ? html`<tr><td colspan="6">No listener samples are available yet.</td></tr>` : nothing}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  private renderSessionActivity() {
    const activity = this.sessionActivity;
    const presentation = this.collectorPresentation(
      activity.state, activity.lastSuccessAtUnixMs, 10_000,
    );
    return html`
      <section class="runtime-summary" aria-label="Session activity">
        <div class="runtime-heading">
          <div><h3>Live session activity</h3><p>Privacy-preserving transport aggregates</p></div>
          <span class="runtime-state ${presentation.tone}" title=${activity.detail}>
            ● ${presentation.label}
          </span>
        </div>
        <div class="metric-grid">
          <article class="metric">
            <span class="metric-label">Observed sessions</span>
            <strong class="metric-value">${activity.total.toLocaleString()}</strong>
            <span class="metric-note">Across ${activity.protocols.length} transports</span>
          </article>
          <article class="metric">
            <span class="metric-label">Current throughput</span>
            <strong class="metric-value">${this.formatBytes(activity.speedUp + activity.speedDown)}/s</strong>
            <span class="metric-note">${this.formatBytes(activity.speedUp)}/s up · ${this.formatBytes(activity.speedDown)}/s down</span>
          </article>
          <article class="metric">
            <span class="metric-label">Last activity sample</span>
            <strong class="metric-value">${activity.checkedAtUnixMs === null ? '—' : new Date(activity.checkedAtUnixMs).toLocaleTimeString()}</strong>
            <span class="metric-note">Last success: ${this.timeLabel(activity.lastSuccessAtUnixMs)}</span>
          </article>
          <article class="metric">
            <span class="metric-label">Privacy boundary</span>
            <strong class="metric-value">Aggregated</strong>
            <span class="metric-note">No endpoints, session IDs, or policy names</span>
          </article>
        </div>
        ${this.renderCollectorNotice(presentation, activity.detail, activity.lastSuccessAtUnixMs)}
        <div class="table">
          <table class="listener-table">
            <thead><tr><th>Transport</th><th>Sessions</th><th>Current up</th><th>Current down</th><th>Transferred</th></tr></thead>
            <tbody>
              ${activity.protocols.map(protocol => html`
                <tr>
                  <td class="listener-name">${protocol.protocol}</td>
                  <td>${protocol.sessions.toLocaleString()}</td>
                  <td>${this.formatBytes(protocol.speedUp)}/s</td>
                  <td>${this.formatBytes(protocol.speedDown)}/s</td>
                  <td>${this.formatBytes(protocol.bytesUp + protocol.bytesDown)}</td>
                </tr>
              `)}
              ${activity.protocols.length === 0 ? html`<tr><td colspan="5">No active session sample is available.</td></tr>` : nothing}
            </tbody>
          </table>
        </div>
        <div class="privacy-note">Source and destination addresses, ports, session identifiers, and policy names remain inside the GUI core.</div>
      </section>
    `;
  }

  private renderSystem() {
    const settings = this.snapshot?.settings;
    const debug = this.snapshot?.debug;
    const captures = this.snapshot?.captures;
    const securityAssets = this.snapshot?.securityAssets;
    const workers = (value: number) => value === -1 ? 'Disabled' : String(value);
    const setting = <T extends ConfigScalar>(path: string, fallback: T): T =>
      this.presentedValue(`settings.${path}`, fallback);
    const settingStrings = (path: string, fallback: ReadonlyArray<string>): ReadonlyArray<string> =>
      this.presentedListValue(`settings.${path}`, fallback, 'string');
    const debugSetting = <T extends ConfigScalar>(path: string, fallback: T): T =>
      this.presentedValue(`debug.${path}`, fallback);
    const captureSetting = <T extends ConfigScalar>(path: string, fallback: T): T =>
      this.presentedValue(`captures.${path}`, fallback);
    const gateway = this.gatewayStatus();
    const capabilityTone = this.capabilityBootstrapState === 'ready' ? 'success' :
      this.capabilityBootstrapState === 'unavailable' ? 'danger' : 'warning';
    const enabledCapabilityCount = this.enabledCapabilityCount();
    const pendingConfiguration = this.draftObjects.has('settings:settings') ||
      this.draftObjects.has('captures:captures') ||
      [...this.draftObjects].some(key => key.startsWith('authority:') || key.startsWith('signature:') ||
        key.startsWith('signature-flow:'));
    return html`
      <div class="content dashboard" tabindex="0">
        <div class="section-head">
          <div><h2>System integration</h2><p>Non-sensitive diagnostics for this GUI instance</p></div>
          <button class="secondary" type="button" @click=${() => this.downloadDiagnostics()}>Download diagnostics</button>
        </div>
        ${pendingConfiguration ? html`<div class="scope-note" role="status">
          Configuration cards include pending workspace draft values. Smithproxy runtime remains unchanged until a validated atomic commit.
        </div>` : nothing}
        <div class="system-grid">
          <article class="domain-card">
            <header><div><h3>GUI core</h3><p>Local API and frontend host</p></div></header>
            <dl>
              <dt>Status</dt><dd>${displayState(this.systemStatus.core)}</dd>
              <dt>Uptime</dt><dd>${this.uptimeLabel()}</dd>
              <dt>API version</dt><dd>${this.apiVersion}</dd>
              <dt>Base path</dt><dd>${this.runtime?.basePath ?? 'discovering'}</dd>
            </dl>
          </article>
          <article class="domain-card">
            <header>
              <div><h3>Capability bootstrap</h3><p>Browser trust and feature boundary</p></div>
              <span class="runtime-state ${capabilityTone}" title=${this.capabilityError ?? ''}>
                ● ${displayState(this.capabilityBootstrapState)}
              </span>
            </header>
            <dl>
              <dt>Last check</dt><dd>${this.timeLabel(this.capabilityCheckedAtUnixMs)}</dd>
              <dt>Last valid contract</dt><dd>${this.timeLabel(this.capabilityLastSuccessAtUnixMs)}</dd>
              <dt>API contract</dt><dd>${this.apiVersion}</dd>
              <dt>Enabled surfaces</dt><dd>${enabledCapabilityCount} / 13</dd>
              <dt>Refresh cadence</dt><dd>30 seconds · connectivity-triggered</dd>
            </dl>
            ${this.capabilityError ? html`<p role="status">${this.capabilityError}</p>` : nothing}
          </article>
          <article class="domain-card">
            <header><div><h3>Smithproxy API</h3><p>Server-side authenticated connection</p></div></header>
            <dl>
              <dt>Status</dt><dd>${displayState(this.systemStatus.smithproxy)}</dd>
              <dt>Last check</dt><dd>${this.timeLabel(this.systemStatus.checkedAtUnixMs)}</dd>
              <dt>Last success</dt><dd>${this.timeLabel(this.systemStatus.lastSuccessAtUnixMs)}</dd>
              <dt>Credential handling</dt><dd>GUI core only</dd>
            </dl>
          </article>
          <article class="domain-card">
            <header><div><h3>Appearance</h3><p>Saslik appearance contract v1</p></div></header>
            <dl>
              <dt>Application scope</dt><dd>smithproxy-gui</dd>
              <dt>Palette source</dt><dd>Saslik shared assets</dd>
              <dt>Fallback</dt><dd>Petroleum dark</dd>
            </dl>
          </article>
          <article class="domain-card">
            <header><div><h3>Security boundary</h3><p>Browser requests stay on the current origin</p></div></header>
            <dl>
              <dt>Browser credentials</dt><dd>Same origin</dd>
              <dt>Smithproxy key</dt><dd>Never exposed</dd>
              <dt>External redirects</dt><dd>Rejected</dd>
            </dl>
          </article>
          <article class="domain-card">
            <header>
              <div><h3>Saslik gateway</h3><p>Trusted per-instance request handoff</p></div>
              <span class="runtime-state ${gateway.tone}" title=${gateway.detail}>● ${gateway.label}</span>
            </header>
            <dl>
              <dt>Core mode</dt><dd>${this.gatewaySession?.mode === 'gateway' ? 'Gateway configured' :
                this.gatewaySession?.mode === 'disabled' ? 'Fail-closed disabled' : 'Unknown'}</dd>
              <dt>Current request</dt><dd>${this.gatewaySession?.authenticated ? 'Verified' : 'Not verified'}</dd>
              <dt>Configuration read</dt><dd>${this.configReadAvailable ? 'Available' : 'Blocked'}</dd>
              <dt>Shared draft</dt><dd>${this.draftAvailable ? 'Available' : 'Blocked'}</dd>
              <dt>Atomic commit</dt><dd>${this.configWriteAvailable ? 'Available' : 'Blocked'}</dd>
              <dt>Upstream transaction</dt><dd>${this.transactionCapabilityState === 'not-advertised' ? 'Not advertised' :
                this.transactionCapabilityState === 'review-required' ? 'Schema review required' :
                this.transactionCapabilityState === 'ready' ? 'Reviewed contract ready' :
                displayState(this.transactionCapabilityState)}</dd>
            </dl>
            <p role="status">${gateway.detail}</p>
          </article>
          <article class="domain-card">
            <header><div><h3>Augment overlays</h3><p>Persistent and effective value provenance</p></div></header>
            <dl>
              <dt>Capability</dt><dd>${this.snapshot?.augmentSupport ? 'Available' : 'Not advertised'}</dd>
              <dt>Tracked values</dt><dd>${this.snapshot?.valueOrigins.length ?? 0}</dd>
              <dt>Editing target</dt><dd>Persistent config</dd>
            </dl>
          </article>
          <article class="domain-card job-card">
            <header>
              <div><h3>Backend jobs</h3><p>Bounded, redacted control-plane work queue</p></div>
              <span class="runtime-state ${this.jobsError ? 'danger' : this.jobsAvailable ? 'success' : 'warning'}">
                ● ${this.jobsError ? 'Unavailable' : this.jobsAvailable ? 'Available' : 'Not advertised'}
              </span>
            </header>
            ${this.jobsError ? html`<p role="alert">${this.jobsError}</p>` : nothing}
            <div class="job-list" aria-label="Recent backend jobs">
              ${[...this.backendJobs.jobs].reverse().slice(0, 5).map(job => html`
                <div class="job-row" title=${job.id}>
                  <strong>${job.type === 'config-refresh' ? 'Configuration refresh' : job.type}</strong>
                  <span>${displayState(job.phase.replaceAll('-', ' '))}<small>${job.result ?? `Deadline ${this.timeLabel(job.deadlineAtUnixMs)}`}</small></span>
                  <span class="job-progress"><progress max="100" .value=${job.progressPercent}></progress><small>${job.progressPercent}%</small></span>
                  <span class="system-state ${job.state === 'succeeded' ? 'success' : job.state === 'failed' || job.state === 'cancelled' ? 'danger' : 'warning'}">${displayState(job.state)}</span>
                </div>
              `)}
              ${this.backendJobs.jobs.length === 0 ? html`<p>No backend jobs have been recorded since this core started.</p>` : nothing}
            </div>
          </article>
          ${settings ? html`
            <article class="domain-card">
              <header><div><h3>Traffic admission</h3><p>Configured listener and failure policy</p></div>
                <div class="preflight-actions">${this.renderPendingBadge('settings', 'settings')}
                  <button class="secondary" type="button" @click=${(event: Event) => this.openSystemDrawer('settings', event.currentTarget as HTMLElement)}>Edit</button>
                </div>
              </header>
              <dl>
                <dt>TPROXY / REDIRECT</dt><dd>${setting('accept_tproxy', settings.acceptTproxy) ? 'On' : 'Off'} / ${setting('accept_redirect', settings.acceptRedirect) ? 'On' : 'Off'}</dd>
                <dt>SOCKS / CONNECT</dt><dd>${setting('accept_socks', settings.acceptSocks) ? 'On' : 'Off'} / ${setting('accept_http_connect', settings.acceptHttpConnect) ? 'On' : 'Off'}</dd>
                <dt>Local destination protection</dt><dd>${setting('extended_local_destination_protection', settings.extendedLocalDestinationProtection) ? 'Enforced' : 'Disabled · unsafe'}</dd>
                <dt>Policy failure</dt><dd>${setting('policy_fail_open', settings.policyFailOpen) ? 'Fail open' : 'Fail closed'}</dd>
                <dt>Access request failure</dt><dd>${setting('policy_access_request_fail_open', settings.accessRequestFailOpen) ? 'Fail open' : 'Fail closed'}</dd>
              </dl>
            </article>
            <article class="domain-card">
              <header><div><h3>Worker pools</h3><p>Configured runtime concurrency</p></div></header>
              <dl>
                <dt>Plaintext / TLS</dt><dd>${workers(setting('plaintext_workers', settings.workers.plaintext))} / ${workers(setting('ssl_workers', settings.workers.tls))}</dd>
                <dt>UDP / DTLS / QUIC</dt><dd>${workers(setting('udp_workers', settings.workers.udp))} / ${workers(setting('dtls_workers', settings.workers.dtls))} / ${workers(setting('quic_workers', settings.workers.quic))}</dd>
                <dt>SOCKS / CONNECT</dt><dd>${workers(setting('socks_workers', settings.workers.socks))} / ${workers(setting('http_connect_workers', settings.workers.httpConnect))}</dd>
                <dt>TLS autodetect</dt><dd>${setting('ssl_autodetect', settings.tlsAutodetect) ? 'Enabled' : 'Disabled'}</dd>
                <dt>Kernel TLS</dt><dd>${setting('ssl_use_ktls', settings.kernelTls) ? 'Requested' : 'Disabled'}</dd>
              </dl>
            </article>
            <article class="domain-card">
              <header><div><h3>Listener endpoints</h3><p>Configured local ports and certificate status caches</p></div></header>
              <dl>
                <dt>Plaintext / TLS</dt><dd>${setting('plaintext_port', settings.ports.plaintext)} / ${setting('ssl_port', settings.ports.tls)}</dd>
                <dt>UDP / QUIC</dt><dd>${setting('udp_port', settings.ports.udp)} / ${setting('quic_port', settings.ports.quic)}</dd>
                <dt>HTTP CONNECT</dt><dd>${setting('http_connect_port', settings.ports.httpConnect)}</dd>
                <dt>OCSP status TTL</dt><dd>${setting('ssl_ocsp_status_ttl', settings.ocspStatusTtl).toLocaleString()} s</dd>
                <dt>CRL status TTL</dt><dd>${setting('ssl_crl_status_ttl', settings.crlStatusTtl).toLocaleString()} s</dd>
              </dl>
            </article>
            <article class="domain-card">
              <header><div><h3>Logging and payloads</h3><p>Destinations stay redacted</p></div></header>
              <dl>
                <dt>Log level / console</dt><dd>${setting('log_level', settings.logging.level)} / ${setting('log_console', settings.logging.console) ? 'On' : 'Off'}</dd>
                <dt>Log file</dt><dd>${settings.logging.fileConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>TLS key log</dt><dd>${settings.logging.sslKeyFileConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>Default payload capture</dt><dd>${setting('default_write_payload', settings.logging.defaultWritePayload) ? 'Enabled' : 'Disabled'}</dd>
                <dt>Payload directory</dt><dd>${settings.logging.payloadDirectoryConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>Single PCAP quota</dt><dd>${setting('write_pcap_single_quota', settings.logging.pcapSingleQuota).toLocaleString()}</dd>
                <dt>Syslog</dt><dd>${settings.logging.syslogServerConfigured ? `Configured · IPv${setting('syslog_family', settings.logging.syslogFamily)}` : 'Not configured'}</dd>
                <dt>Syslog port / facility / level</dt><dd>${setting('syslog_port', settings.logging.syslogPort)} / ${setting('syslog_facility', settings.logging.syslogFacility)} / ${setting('syslog_level', settings.logging.syslogLevel)}</dd>
              </dl>
            </article>
            <article class="domain-card">
              <header><div><h3>Auxiliary services</h3><p>Credentials and filesystem paths stay redacted</p></div></header>
              <dl>
                <dt>CLI port / password</dt><dd>${setting('cli.port', settings.auxiliary.cliPort)} / ${settings.auxiliary.cliPasswordConfigured ? 'Configured' : 'Not configured'}</dd>
                <dt>SOCKS async DNS</dt><dd>${setting('socks.async_dns', settings.auxiliary.socksAsyncDns) ? 'Enabled' : 'Disabled'}</dd>
                <dt>Host buffer</dt><dd>${setting('tuning.host_bufsz_min', settings.auxiliary.tuning.hostBufferMin)} bytes</dd>
                <dt>Neighbor cache</dt><dd>${setting('tuning.nbr_cache_size', settings.auxiliary.tuning.neighborCacheSize)} entries</dd>
                <dt>UDP quick ports</dt><dd>${settingStrings('udp_quick_ports', settings.auxiliary.udpQuickPorts).join(', ') || 'None'}</dd>
                <dt>Certificates / CA bundle</dt><dd>${settings.auxiliary.certificatesPathConfigured ? 'Configured' : 'Missing'} / ${settings.auxiliary.caBundlePathConfigured ? 'Configured' : 'Missing'}</dd>
                <dt>CA password</dt><dd>${settings.auxiliary.certificatePasswordConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>Message assets</dt><dd>${settings.auxiliary.messagesDirectoryConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>Payload filename parts</dt><dd>${settings.auxiliary.payloadFilePrefixConfigured ? 'Prefix' : 'No prefix'} / ${settings.auxiliary.payloadFileSuffixConfigured ? 'Suffix' : 'No suffix'}</dd>
                <dt>Web rating key</dt><dd>${settings.auxiliary.webRatingKeyConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
              </dl>
            </article>
            <article class="domain-card">
              <header><div><h3>Smithproxy API posture</h3><p>Secrets and addresses are redacted</p></div></header>
              <dl>
                <dt>Listener</dt><dd>${setting('accept_api', settings.acceptApi) ? 'Enabled' : 'Disabled'}</dd>
                <dt>API keys</dt><dd>${settings.httpApi.keyCount} configured</dd>
                <dt>Allowed IPs</dt><dd>${settingStrings('http_api.allowed_ips', settings.httpApi.allowedIps).join(', ') || 'None'}</dd>
                <dt>Listener</dt><dd>Port ${setting('http_api.port', settings.httpApi.port)} · ${setting('http_api.key_timeout', settings.httpApi.keyTimeout)}s token TTL</dd>
                <dt>Token refresh</dt><dd>${setting('http_api.key_extend_on_access', settings.httpApi.keyExtendOnAccess) ? 'On access' : 'Fixed expiry'}</dd>
                <dt>Loopback only</dt><dd>${setting('http_api.loopback_only', settings.httpApi.loopbackOnly) ? 'Yes' : 'No'}</dd>
                <dt>Bind address</dt><dd>${settings.httpApi.bindAddressConfigured ? 'Configured · redacted' : 'Default'}</dd>
                <dt>Bind interface</dt><dd>${settings.httpApi.bindInterfaceConfigured ? 'Configured · redacted' : 'Default'}</dd>
                <dt>API header access</dt><dd>${setting('http_api.allow_api_header', settings.httpApi.allowApiHeader) ? 'Allowed' : 'Blocked'}</dd>
                <dt>PAM login</dt><dd>${setting('http_api.pam_login', settings.httpApi.pamLogin) ? 'Enabled' : 'Disabled'}</dd>
              </dl>
            </article>
            <article class="domain-card">
              <header><div><h3>Webhook posture</h3><p>URLs and identities are redacted</p></div></header>
              <dl>
                <dt>Webhook</dt><dd>${setting('webhook.enabled', settings.webhook.enabled) ? 'Enabled' : 'Disabled'}</dd>
                <dt>URL</dt><dd>${settings.webhook.urlConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>TLS verification</dt><dd>${setting('webhook.tls_verify', settings.webhook.tlsVerify) ? 'Required' : 'Disabled'}</dd>
                <dt>Sift</dt><dd>${setting('webhook.sift', settings.webhook.siftEnabled) ? 'Enabled' : 'Disabled'}</dd>
                <dt>Sift endpoint</dt><dd>${settings.webhook.siftUrlConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>Sift payload limit</dt><dd>${setting('webhook.sift_payload_limit_per_direction', settings.webhook.siftPayloadLimitPerDirection)} bytes / direction</dd>
                <dt>LoreD enrichment</dt><dd>${setting('webhook.sift_lored_mode', settings.webhook.siftLoredMode)}</dd>
                <dt>LoreD URL disclosure</dt><dd>${setting('webhook.sift_lored_include_url', settings.webhook.siftLoredIncludeUrl) ? 'Allowed' : 'Blocked'}</dd>
                <dt>Ping interval</dt><dd>${setting('webhook.ping_interval', settings.webhook.pingInterval)}s</dd>
                <dt>API override</dt><dd>${setting('webhook.api_override', settings.webhook.apiOverride) ? 'Allowed' : 'Blocked'}</dd>
                <dt>Nameservers</dt><dd>${settingStrings('nameservers', settings.nameservers).join(', ') || 'None'}</dd>
              </dl>
            </article>
          ` : nothing}
          ${debug ? html`
            <article class="domain-card">
              <header><div><h3>Debug logging</h3><p>Potentially expensive diagnostic controls</p></div>
                <div class="preflight-actions">${this.renderPendingBadge('settings', 'settings')}
                  <button class="secondary" type="button" @click=${(event: Event) => this.openSystemDrawer('settings', event.currentTarget as HTMLElement)}>Edit</button>
                </div>
              </header>
              <dl>
                <dt>Payload CRC</dt><dd>${debugSetting('log_data_crc', debug.logDataCrc) ? 'Enabled' : 'Disabled'}</dd>
                <dt>Socket events</dt><dd>${debugSetting('log_sockets', debug.logSockets) ? 'Enabled' : 'Disabled'}</dd>
                <dt>Resolve online names</dt><dd>${debugSetting('log_online_cx_name', debug.logOnlineConnectionName) ? 'Enabled · expensive' : 'Disabled'}</dd>
                <dt>Source lines</dt><dd>${debugSetting('log_srclines_always', debug.logSourceLinesAlways) ? 'Always' : debugSetting('log_srclines', debug.logSourceLines) ? 'Diagnostic levels' : 'Disabled'}</dd>
                <dt>Module overrides</dt><dd>${debug.moduleOverrideCount} configured</dd>
              </dl>
            </article>
          ` : nothing}
          ${captures ? html`
            <article class="domain-card">
              <header><div><h3>Capture posture</h3><p>Paths and destinations are redacted</p></div>
                <div class="preflight-actions">${this.renderPendingBadge('captures', 'captures')}
                  <button class="secondary" type="button" @click=${(event: Event) => this.openSystemDrawer('captures', event.currentTarget as HTMLElement)}>Edit</button>
                </div>
              </header>
              <dl>
                <dt>Local capture</dt><dd>${captureSetting('local.enabled', captures.local.enabled) ? 'Enabled' : 'Disabled'}</dd>
                <dt>Local target</dt><dd>${captures.local.directoryConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>Filename prefix / suffix</dt><dd>${captures.local.filePrefixConfigured ? 'Configured' : 'Empty'} / ${captures.local.fileSuffixConfigured ? 'Configured' : 'Empty'}</dd>
                <dt>Format / quota</dt><dd>${captureSetting('local.format', captures.local.format)} / ${captureSetting('local.pcap_quota', captures.local.quotaMiB)} MiB</dd>
                <dt>Remote capture</dt><dd>${captureSetting('remote.enabled', captures.remote.enabled) ? 'Enabled' : 'Disabled'}</dd>
                <dt>Tunnel format</dt><dd>${captureSetting('remote.tun_type', captures.remote.tunnelType)} / ${captureSetting('remote.gre_format', captures.remote.greFormat)}</dd>
                <dt>Remote target</dt><dd>${captures.remote.destinationConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>TTL / bound interface</dt><dd>${captureSetting('remote.tun_ttl', captures.remote.ttl)} / ${captures.remote.bindInterfaceConfigured ? 'Yes' : 'No'}</dd>
                <dt>Checksums</dt><dd>${captureSetting('options.calculate_checksums', captures.calculateChecksums) ? 'Calculated' : 'Preserved'}</dd>
              </dl>
            </article>
          ` : nothing}
          ${securityAssets ? html`
            <article class="domain-card">
              <header><div><h3>Trust and signatures</h3><p>Paths and expressions use write-only controls</p></div></header>
              <dl>
                <dt>Certificate authorities</dt><dd>${securityAssets.certificateAuthorityCount}</dd>
                <dt>CA paths configured</dt><dd>${securityAssets.certificateAuthorityPathCount}</dd>
                <dt>STARTTLS signatures</dt><dd>${securityAssets.starttlsSignatureCount}</dd>
                <dt>STARTTLS flow steps</dt><dd>${securityAssets.starttlsFlowStepCount}</dd>
                <dt>Detection signatures</dt><dd>${securityAssets.detectionSignatureCount}</dd>
                <dt>Detection flow steps</dt><dd>${securityAssets.detectionFlowStepCount}</dd>
              </dl>
              <div class="reference-stack section" role="group" aria-label="Certificate authorities">
                ${securityAssets.certificateAuthorities.length === 0
                  ? html`<span>No certificate authorities configured.</span>`
                  : securityAssets.certificateAuthorities.map(authority => html`
                    <button class="reference" type="button"
                      @click=${(event: MouseEvent) => this.openAuthority(
                        authority.id, event.currentTarget as HTMLElement,
                      )}>
                      <span><strong>${this.authorityDisplayName(authority.id, authority.name)}</strong> · ${authority.pathConfigured ? 'path configured' : 'path missing'}</span>
                      <span aria-hidden="true">→</span>
                    </button>
                  `)}
              </div>
              ${(['starttls', 'detection'] as const).map(kind => html`
                <details class="section">
                  <summary>${kind === 'starttls' ? 'STARTTLS' : 'Detection'} signatures</summary>
                  <div class="reference-stack" role="group"
                    aria-label="${kind === 'starttls' ? 'STARTTLS' : 'Detection'} signatures">
                    ${securityAssets.signatures.filter(item => item.kind === kind).map(signature => html`
                      <button class="reference" type="button"
                        @click=${(event: MouseEvent) => this.openSignature(
                          signature.id, event.currentTarget as HTMLElement,
                        )}>
                        <span><strong>${this.signatureDisplayName(signature.id, signature.name)}</strong> · ${signature.flow.length} flow step${signature.flow.length === 1 ? '' : 's'}</span>
                        <span aria-hidden="true">→</span>
                      </button>
                    `)}
                  </div>
                </details>
              `)}
            </article>
          ` : nothing}
        </div>
      </div>
    `;
  }

  private renderLogs() {
    const allEvents = [...this.operationalEvents.events].reverse();
    const events = this.eventCategoryFilter === 'all'
      ? allEvents
      : allEvents.filter(event => event.category === this.eventCategoryFilter);
    const controlPlaneCount = allEvents.filter(event => event.category === 'control-plane').length;
    const jobEventCount = allEvents.length - controlPlaneCount;
    const auditEntries = [...this.managementAudit.entries].reverse();
    return html`
      <div class="content dashboard" tabindex="0">
        <div class="section-head">
          <div>
            <h2>Operational events</h2>
            <p>Bounded, privacy-safe control-plane and backend-job transitions from the GUI core.</p>
          </div>
          <span class="runtime-state ${this.eventsError ? 'danger' : 'success'}">
            ${this.eventsError ? 'Unavailable' : this.eventCategoryFilter === 'all'
              ? `${events.length} events`
              : `${events.length} of ${allEvents.length} events`}
          </span>
        </div>
        <div class="privacy-note">
          Smithproxy event-ring messages require a future authenticated Smithproxy HTTP API.
          This view intentionally does not parse the administrative CLI or expose arbitrary log text.
        </div>
        <div class="event-filters" role="group" aria-label="Operational event category">
          ${([
            ['all', `All · ${allEvents.length}`],
            ['control-plane', `Control plane · ${controlPlaneCount}`],
            ['backend-job', `Backend jobs · ${jobEventCount}`],
          ] as const).map(([category, label]) => html`
            <button class="secondary" type="button"
              aria-pressed=${this.eventCategoryFilter === category}
              @click=${() => { this.eventCategoryFilter = category; }}>${label}</button>
          `)}
        </div>
        ${this.eventsError ? html`<div class="metrics-message">${this.eventsError}</div>` : nothing}
        ${events.length === 0 ? html`
          <div class="metrics-message">No matching operational event has been observed yet.</div>
        ` : html`
          <div class="event-list" role="list" aria-label="Operational events">
            ${events.map(event => html`
              <article class="event-row" role="listitem">
                <time class="event-time" datetime=${new Date(event.occurredAtUnixMs).toISOString()}>
                  ${new Date(event.occurredAtUnixMs).toLocaleString()}
                </time>
                <span class="event-severity ${event.severity}">${event.severity}</span>
                <strong>${event.message}</strong>
                <span class="event-source" title=${event.code}>${event.category === 'backend-job' ? 'backend job' : 'control plane'}</span>
              </article>
            `)}
          </div>
        `}

        <div class="section-head section">
          <div>
            <h2>Management audit</h2>
            <p>Bounded, redacted GUI-core records for management mutation attempts.</p>
          </div>
          <span class="runtime-state ${this.auditError ? 'danger' : 'success'}">
            ${this.auditError ? 'Unavailable' : `${auditEntries.length} records`}
          </span>
        </div>
        <div class="origin-note">
          <strong>Actor attribution unavailable.</strong>
          The current Saslik gateway contract authenticates the request but does not yet provide a reviewed user identity header.
          Request IDs, operation names and configuration paths are recorded; values and secrets are never included.
        </div>
        ${this.auditError ? html`<div class="metrics-message">${this.auditError}</div>` : nothing}
        ${auditEntries.length === 0 ? html`
          <div class="metrics-message">No management mutation has been observed since the GUI core started.</div>
        ` : html`
          <div class="event-list" role="list" aria-label="Management audit">
            ${auditEntries.map(entry => {
              const tone = entry.outcome === 'succeeded' ? 'info' : entry.outcome === 'conflict' ? 'warning' : 'error';
              const remainingTargets = Math.max(0, entry.targetCount - entry.targets.length);
              const targets = entry.targets.length === 0
                ? 'No accepted target path'
                : `${entry.targets.join(', ')}${remainingTargets > 0 ? ` · +${remainingTargets} omitted` : ''}`;
              return html`
                <article class="audit-row" role="listitem">
                  <time class="event-time" datetime=${new Date(entry.occurredAtUnixMs).toISOString()}>
                    ${new Date(entry.occurredAtUnixMs).toLocaleString()}
                  </time>
                  <span class="event-severity ${tone}">${entry.outcome}</span>
                  <div class="audit-operation"><strong>${entry.operation}</strong><small title=${targets}>${targets}</small></div>
                  <code class="audit-request" title=${entry.requestId}>${entry.requestId}</code>
                </article>
              `;
            })}
          </div>
        `}
      </div>
    `;
  }

  private renderContent() {
    if (this.activeSection === 'Search') return this.renderSearchResults();
    if (this.activeSection === 'Draft') {
      return this.renderDraftReview();
    }
    if (this.activeSection === 'Dashboard') {
      return this.renderDashboard();
    }
    if (this.activeSection === 'Policy') {
      return this.renderPolicyList();
    }
    if (this.activeSection === 'Network') {
      return this.renderNetwork();
    }
    if (this.activeSection === 'Objects') {
      return this.renderObjects();
    }
    if (this.activeSection === 'Monitoring') {
      return this.renderMonitoring();
    }
    if (this.activeSection === 'Logs') {
      return this.renderLogs();
    }
    if (this.activeSection === 'System') {
      return this.renderSystem();
    }
    return html`
      <div class="empty-state">
        <h2>${this.activeSection}</h2>
        <p>This section is reserved in the application shell and will be implemented in a dedicated vertical slice.</p>
      </div>
    `;
  }

  private pendingPolicyCreate(entry: DrawerEntry): DraftCreateOperation | undefined {
    const operation = this.workspaceDraft?.structuralOperations.find(
      item => item.op === 'create' && item.collection === 'policy' && item.localId === entry.id,
    );
    return operation?.op === 'create' ? operation : undefined;
  }

  private renderPolicyCreateEditor(entry: DrawerEntry) {
    const operation = this.pendingPolicyCreate(entry);
    const scalar = (name: string, fallback: DraftScalar): DraftScalar => operation?.fields[name] ?? fallback;
    const text = (name: string, fallback = '') => String(scalar(name, fallback));
    const list = (name: string, fallback: ReadonlyArray<string> = []) => {
      const value = scalar(name, [...fallback]);
      return Array.isArray(value) && value.every(item => typeof item === 'string')
        ? value as ReadonlyArray<string> : fallback;
    };
    const readOnly = !this.structuralDraftsAvailable;
    const placement = operation?.position.kind === 'before'
      ? `before:${operation.position.reference ?? ''}`
      : operation?.position.kind ?? 'last';
    const referenceField = (id: string, label: string, type: string, field: string) => {
      const inputId = `policy-create-${id}-${entry.id}`;
      const value = text(field);
      return html`<label for=${inputId}>${label}</label>
        <div class="reference-edit"><input id=${inputId} .value=${value} data-reference-preview="true"
          maxlength="128" .readOnly=${readOnly} />
          ${this.renderProfileReference(entry, inputId, type, value)}</div>`;
    };
    const sources = list('src', ['any']);
    const destinations = list('dst', ['any']);
    const sourcePorts = list('sport');
    const destinationPorts = list('dport');
    return html`
      <div class="form-grid wide-form-grid">
        <label for="policy-create-name-${entry.id}">Name</label>
        <input id="policy-create-name-${entry.id}" .value=${text('name')} maxlength="128" required
          autocomplete="off" .readOnly=${readOnly} />
        <label for="policy-create-placement-${entry.id}">Placement</label>
        <select id="policy-create-placement-${entry.id}" ?disabled=${readOnly}>
          <option value="first" ?selected=${placement === 'first'}>First policy</option>
          ${this.snapshot?.policies.map(policy => html`
            <option value=${`before:${policy.id}`} ?selected=${placement === `before:${policy.id}`}>
              Before ${policy.name}
            </option>
          `)}
          <option value="last" ?selected=${placement === 'last'}>Last policy</option>
        </select>
        <label>Enabled</label>
        <label><input id="policy-create-enabled-${entry.id}" type="checkbox"
          .checked=${Boolean(scalar('disabled', false)) === false} ?disabled=${readOnly} />
          Accept traffic for evaluation</label>
        <span></span><span></span>
        <label for="policy-create-sources-${entry.id}">Sources</label>
        <div class="reference-stack">
          <input id="policy-create-sources-${entry.id}" .value=${sources.join(', ')}
            data-reference-preview="true" .readOnly=${readOnly} />
          ${this.renderAddressReferences(entry, `policy-create-sources-${entry.id}`, sources)}
        </div>
        <label for="policy-create-destinations-${entry.id}">Destinations</label>
        <div class="reference-stack">
          <input id="policy-create-destinations-${entry.id}" .value=${destinations.join(', ')}
            data-reference-preview="true" .readOnly=${readOnly} />
          ${this.renderAddressReferences(entry, `policy-create-destinations-${entry.id}`, destinations)}
        </div>
        <label for="policy-create-action-${entry.id}">Action</label>
        <input id="policy-create-action-${entry.id}" .value=${text('action', 'accept')}
          maxlength="32" required .readOnly=${readOnly} />
        <label for="policy-create-protocol-${entry.id}">Protocol</label>
        <div class="reference-edit">
          <input id="policy-create-protocol-${entry.id}" .value=${text('proto', 'tcp')}
            data-reference-preview="true" maxlength="128" required .readOnly=${readOnly} />
          ${this.renderProtocolReference(entry, `policy-create-protocol-${entry.id}`, text('proto', 'tcp'))}
        </div>
        <label for="policy-create-source-ports-${entry.id}">Source ports</label>
        <div class="reference-stack">
          <input id="policy-create-source-ports-${entry.id}" .value=${sourcePorts.join(', ')}
            data-reference-preview="true" .readOnly=${readOnly} />
          ${this.renderPortReferences(entry, `policy-create-source-ports-${entry.id}`, sourcePorts)}
        </div>
        <label for="policy-create-destination-ports-${entry.id}">Destination ports</label>
        <div class="reference-stack">
          <input id="policy-create-destination-ports-${entry.id}" .value=${destinationPorts.join(', ')}
            data-reference-preview="true" .readOnly=${readOnly} />
          ${this.renderPortReferences(entry, `policy-create-destination-ports-${entry.id}`, destinationPorts)}
        </div>
        ${referenceField('tls', 'TLS profile', 'tls', 'tls_profile')}
        ${referenceField('routing', 'Routing profile', 'routing', 'routing')}
        ${referenceField('detection', 'Detection profile', 'detection', 'detection_profile')}
        ${referenceField('content', 'Content profile', 'content', 'content_profile')}
        ${referenceField('ssh', 'SSH profile', 'ssh', 'ssh_profile')}
        ${referenceField('auth', 'Authentication profile', 'authentication', 'auth_profile')}
        ${referenceField('dns', 'DNS ALG profile', 'dns', 'alg_dns_profile')}
        ${referenceField('script', 'Script profile', 'script', 'script_profile')}
        <label for="policy-create-features-${entry.id}">Features</label>
        <input id="policy-create-features-${entry.id}" .value=${list('features').join(', ')}
          .readOnly=${readOnly} />
        <label for="policy-create-nat-${entry.id}">NAT</label>
        <input id="policy-create-nat-${entry.id}" .value=${text('nat')} maxlength="128"
          .readOnly=${readOnly} />
      </div>
      <div class="impact">
        Policy order affects traffic decisions. This operation remains in the workspace draft until Smithproxy
        validates and atomically commits it.
      </div>
    `;
  }

  private renderPolicyEditor(entry: DrawerEntry) {
    const policy = this.snapshot?.policies.find(item => item.id === entry.id);
    if (!policy) return nothing;
    const policyIndex = this.snapshot?.policies.findIndex(item => item.id === entry.id) ?? -1;
    const policyBase = `policy.[${policyIndex}]`;
    const liveReadOnly = this.snapshot?.source === 'live' && !this.draftAvailable;
    const protocolValue = this.persistentValue(`${policyBase}.proto`, policy.protocol);
    const sourceValues = this.persistentListValue(
      `${policyBase}.src`, policy.sources.map(item => item.name), 'string',
    );
    const destinationValues = this.persistentListValue(
      `${policyBase}.dst`, policy.destinations.map(item => item.name), 'string',
    );
    const sourcePortValues = this.persistentListValue(`${policyBase}.sport`, policy.sourcePorts, 'string');
    const destinationPortValues = this.persistentListValue(`${policyBase}.dport`, policy.destinationPorts, 'string');
    const featureValues = this.persistentListValue(`${policyBase}.features`, policy.features, 'string');
    const protocol = this.snapshot?.protocols.find(item => item.name === protocolValue);
    return html`
      <div class="form-grid">
        <label for="policy-name-${entry.id}">Name</label>
        <input id="policy-name-${entry.id}" .value=${this.persistentValue(`${policyBase}.name`, policy.name)}
          .readOnly=${this.originReadOnly(`${policyBase}.name`, liveReadOnly)} />
        <label>Enabled</label>
        <label><input id="policy-enabled-${entry.id}" type="checkbox"
          .checked=${!this.persistentValue(`${policyBase}.disabled`, !policy.enabled)}
          ?disabled=${this.originReadOnly(`${policyBase}.disabled`, liveReadOnly)} /> Accept traffic for evaluation</label>
        <label for="policy-sources-${entry.id}">Sources</label>
        <div class="reference-stack">
          <input id="policy-sources-${entry.id}" .value=${sourceValues.join(', ')}
            data-reference-preview="true"
            .readOnly=${this.originReadOnly(`${policyBase}.src`, liveReadOnly)} />
          ${this.renderAddressReferences(entry, `policy-sources-${entry.id}`, sourceValues)}</div>
        <label for="destination-${entry.id}">Destinations</label>
        <div class="reference-stack">
          <input id="destination-${entry.id}"
            .value=${destinationValues.join(', ')}
            data-reference-preview="true"
            .readOnly=${this.originReadOnly(`${policyBase}.dst`, liveReadOnly)} />
          ${this.renderAddressReferences(entry, `destination-${entry.id}`, destinationValues)}
        </div>
        <label for="action-${entry.id}">Action</label>
        <input id="action-${entry.id}" .value=${this.persistentValue(`${policyBase}.action`, policy.action)}
          .readOnly=${this.originReadOnly(`${policyBase}.action`, liveReadOnly)} />
      </div>
      <div class="section">
        <h3>Advanced</h3>
        <div class="form-grid">
          <label for="policy-protocol-${entry.id}">Protocol</label>
          <div class="reference-edit"><input id="policy-protocol-${entry.id}" .value=${protocolValue}
            data-reference-preview="true"
            .readOnly=${this.originReadOnly(`${policyBase}.proto`, liveReadOnly)} />
            ${this.renderProtocolReference(entry, `policy-protocol-${entry.id}`, protocol?.name ?? protocolValue)}</div>
          <label for="policy-source-ports-${entry.id}">Source ports</label>
          <div class="reference-stack"><input id="policy-source-ports-${entry.id}"
            .value=${sourcePortValues.join(', ')}
            data-reference-preview="true"
            .readOnly=${this.originReadOnly(`${policyBase}.sport`, liveReadOnly)} />${this.renderPortReferences(entry, `policy-source-ports-${entry.id}`, sourcePortValues)}</div>
          <label for="policy-destination-ports-${entry.id}">Destination ports</label>
          <div class="reference-stack"><input id="policy-destination-ports-${entry.id}"
            .value=${destinationPortValues.join(', ')}
            data-reference-preview="true"
            .readOnly=${this.originReadOnly(`${policyBase}.dport`, liveReadOnly)} />${this.renderPortReferences(entry, `policy-destination-ports-${entry.id}`, destinationPortValues)}</div>
          ${this.renderPolicyProfileField(entry, 'tls', 'TLS profile', 'tls', policy.tlsProfile, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'routing', 'Routing profile', 'routing', policy.routing, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'detection', 'Detection profile', 'detection', policy.detectionProfile, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'content', 'Content profile', 'content', policy.contentProfile, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'ssh', 'SSH profile', 'ssh', policy.sshProfile, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'auth', 'Authentication profile', 'authentication', policy.authProfile, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'dns', 'DNS ALG profile', 'dns', policy.dnsProfile, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'script', 'Script profile', 'script', policy.scriptProfile, liveReadOnly)}
          <label for="policy-features-${entry.id}">Features</label>
          <input id="policy-features-${entry.id}" .value=${featureValues.join(', ')}
            .readOnly=${this.originReadOnly(`${policyBase}.features`, liveReadOnly)} />
          <label for="policy-nat-${entry.id}">NAT</label>
          <input id="policy-nat-${entry.id}" .value=${this.persistentValue(`${policyBase}.nat`, policy.nat)}
            .readOnly=${this.originReadOnly(`${policyBase}.nat`, liveReadOnly)} />
        </div>
      </div>
    `;
  }

  private previewReferenceNames(
    entry: DrawerEntry, inputId: string, fallback: ReadonlyArray<string>,
  ): ReadonlyArray<string> {
    const current = this.referencePreviewValues.get(`${this.drawerKey(entry)}|${inputId}`);
    return current === undefined
      ? fallback
      : current.split(',').map(value => value.trim()).filter(Boolean);
  }

  private renderReferenceAdvisory(name: string) {
    return html`<span class="reference-advisory">
      <strong>${name}</strong><small>Literal or unresolved</small>
    </span>`;
  }

  private renderAddressReferences(entry: DrawerEntry, inputId: string, fallback: ReadonlyArray<string>) {
    const names = this.previewReferenceNames(entry, inputId, fallback);
    return html`${names.map(name => {
      const reference = this.snapshot?.addresses.find(item => item.name === name);
      return reference ? html`
        <button class="reference" type="button"
          @click=${(event: MouseEvent) => this.openAddress(reference.id, event.currentTarget as HTMLElement)}>
          <span>${reference.name}</span><span aria-hidden="true">→</span>
        </button>
      ` : this.renderReferenceAdvisory(name);
    })}`;
  }

  private renderPortReferences(entry: DrawerEntry, inputId: string, fallback: ReadonlyArray<string>) {
    const names = this.previewReferenceNames(entry, inputId, fallback);
    return html`<div class="reference-stack">${names.map(name => {
      const port = this.snapshot?.ports.find(item => item.name === name);
      return port ? html`<button class="reference" type="button"
        @click=${(event: MouseEvent) => this.openPort(port.id, event.currentTarget as HTMLElement)}>
        <span>${port.name}</span><span aria-hidden="true">→</span>
      </button>` : this.renderReferenceAdvisory(name);
    })}</div>`;
  }

  private renderProtocolReference(entry: DrawerEntry, inputId: string, fallback: string) {
    const name = this.previewReferenceNames(entry, inputId, [fallback])[0] ?? '';
    if (name.length === 0) return nothing;
    const protocol = this.snapshot?.protocols.find(item => item.name === name);
    return protocol ? html`<button class="reference" type="button"
      @click=${(event: MouseEvent) => this.openProtocol(protocol.id, event.currentTarget as HTMLElement)}>
      <span>${protocol.name}</span><span aria-hidden="true">→</span>
    </button>` : this.renderReferenceAdvisory(name);
  }

  private renderProfileReference(entry: DrawerEntry, inputId: string, type: string, fallback: string) {
    const name = this.previewReferenceNames(entry, inputId, [fallback])[0] ?? '';
    if (name.length === 0 || name === 'none') return html`<span>None</span>`;
    const profile = this.snapshot?.profiles.find(item => item.type === type && item.name === name);
    return profile ? html`<button class="reference" type="button"
      @click=${(event: MouseEvent) => this.openProfile(profile.id, event.currentTarget as HTMLElement)}>
      <span>${profile.name}</span><span aria-hidden="true">→</span>
    </button>` : this.renderReferenceAdvisory(name);
  }

  private renderPolicyProfileField(
    entry: DrawerEntry, id: string, label: string, type: string, value: string, readOnly: boolean,
  ) {
    const policyIndex = this.snapshot?.policies.findIndex(item => item.id === entry.id) ?? -1;
    const fields: Readonly<Record<string, string>> = {
      tls: 'tls_profile', routing: 'routing', detection: 'detection_profile', content: 'content_profile',
      ssh: 'ssh_profile', auth: 'auth_profile', dns: 'alg_dns_profile', script: 'script_profile',
    };
    const path = `policy.[${policyIndex}].${fields[id] ?? id}`;
    const persistent = this.persistentValue(path, value);
    const inputId = `policy-${id}-${entry.id}`;
    return html`<label for="policy-${id}-${entry.id}">${label}</label>
      <div class="reference-edit"><input id=${inputId} .value=${persistent} data-reference-preview="true"
        .readOnly=${this.originReadOnly(path, readOnly)} />
        ${this.renderProfileReference(entry, inputId, type, persistent)}</div>`;
  }

  private renderAddressEditor(entry: DrawerEntry) {
    const address = this.snapshot?.addresses.find(item => item.id === entry.id);
    if (!address) return nothing;
    const index = this.snapshot?.addresses.findIndex(item => item.id === entry.id) ?? -1;
    const base = `address_objects.[${index}]`;
    const readOnly = this.snapshot?.source === 'live' && !this.draftAvailable;
    return html`
      <div class="form-grid">
        <label for="address-name-${entry.id}">Name</label>
        <input id="address-name-${entry.id}" .value=${this.persistentValue(`${base}.name`, address.name)}
          .readOnly=${this.originReadOnly(`${base}.name`, readOnly)} />
        <label for="address-type-${entry.id}">Type</label>
        <select id="address-type-${entry.id}" .value=${this.persistentValue(`${base}.type`, address.type)}
          ?disabled=${this.originReadOnly(`${base}.type`, readOnly)}>
          <option value="cidr">CIDR</option><option value="fqdn">FQDN</option><option value="host">Host</option><option value="subnet">Subnet</option><option value="range">Range</option>
        </select>
        <label for="address-value-${entry.id}">Address</label>
        <input id="address-value-${entry.id}" .value=${this.persistentValue(`${base}.value`, address.value)}
          .readOnly=${this.originReadOnly(`${base}.value`, readOnly)} />
      </div>
      ${this.renderObjectUsage(address)}
    `;
  }

  private pendingAddressCreate(entry: DrawerEntry): DraftCreateOperation | undefined {
    const operation = this.workspaceDraft?.structuralOperations.find(
      item => item.op === 'create' && item.collection === 'address_objects' && item.localId === entry.id,
    );
    return operation?.op === 'create' ? operation : undefined;
  }

  private renderAddressCreateEditor(entry: DrawerEntry) {
    const operation = this.pendingAddressCreate(entry);
    const field = (name: string, fallback: DraftScalar): DraftScalar => operation?.fields[name] ?? fallback;
    const name = String(field('name', ''));
    const type = String(field('type', 'cidr'));
    const value = String(field('value', ''));
    const readOnly = !this.structuralDraftsAvailable;
    return html`
      <div class="form-grid">
        <label for="address-create-name-${entry.id}">Name</label>
        <input id="address-create-name-${entry.id}" .value=${name} maxlength="128" required
          autocomplete="off" .readOnly=${readOnly} />
        <label for="address-create-type-${entry.id}">Type</label>
        <select id="address-create-type-${entry.id}" .value=${type} ?disabled=${readOnly}>
          <option value="cidr">CIDR</option><option value="fqdn">FQDN</option>
          <option value="host">Host</option><option value="subnet">Subnet</option>
          <option value="range">Range</option>
        </select>
        <label for="address-create-value-${entry.id}">Address</label>
        <input id="address-create-value-${entry.id}" .value=${value} maxlength="1024" required
          autocomplete="off" .readOnly=${readOnly} />
      </div>
      <div class="impact">
        The new object is retained only in the workspace draft until Smithproxy validates and commits the transaction.
      </div>
    `;
  }

  private renderPortCreateEditor(entry: DrawerEntry) {
    const operation = this.pendingSimpleObjectCreate(entry);
    const name = String(operation?.fields['name'] ?? '');
    const start = Number(operation?.fields['start'] ?? 0);
    const end = Number(operation?.fields['end'] ?? 65535);
    const readOnly = !this.structuralDraftsAvailable;
    return html`
      <div class="form-grid">
        <label for="port-create-name-${entry.id}">Name</label>
        <input id="port-create-name-${entry.id}" .value=${name} maxlength="128" required
          autocomplete="off" .readOnly=${readOnly} />
        <label for="port-create-start-${entry.id}">First port</label>
        <input id="port-create-start-${entry.id}" type="number" min="0" max="65535" step="1"
          .value=${String(start)} required .readOnly=${readOnly} />
        <label for="port-create-end-${entry.id}">Last port</label>
        <input id="port-create-end-${entry.id}" type="number" min="0" max="65535" step="1"
          .value=${String(end)} required .readOnly=${readOnly} />
      </div>
      <div class="impact">
        The port range is retained only in the workspace draft until Smithproxy validates and commits it.
      </div>
    `;
  }

  private renderProtocolCreateEditor(entry: DrawerEntry) {
    const operation = this.pendingSimpleObjectCreate(entry);
    const name = String(operation?.fields['name'] ?? '');
    const number = Number(operation?.fields['id'] ?? 6);
    const readOnly = !this.structuralDraftsAvailable;
    return html`
      <div class="form-grid">
        <label for="protocol-create-name-${entry.id}">Name</label>
        <input id="protocol-create-name-${entry.id}" .value=${name} maxlength="128" required
          autocomplete="off" .readOnly=${readOnly} />
        <label for="protocol-create-number-${entry.id}">IP protocol number</label>
        <input id="protocol-create-number-${entry.id}" type="number" min="0" max="255" step="1"
          .value=${String(number)} required .readOnly=${readOnly} />
      </div>
      <div class="impact">
        The protocol object is retained only in the workspace draft until Smithproxy validates and commits it.
      </div>
    `;
  }

  private renderPortEditor(entry: DrawerEntry) {
    const port = this.snapshot?.ports.find(item => item.id === entry.id);
    if (!port) return nothing;
    const index = this.snapshot?.ports.findIndex(item => item.id === entry.id) ?? -1;
    const base = `port_objects.[${index}]`;
    const readOnly = this.snapshot?.source === 'live' && !this.draftAvailable;
    return html`
      <div class="form-grid">
        <label for="port-name-${entry.id}">Name</label>
        <input id="port-name-${entry.id}" .value=${this.persistentValue(`${base}.name`, port.name)}
          .readOnly=${this.originReadOnly(`${base}.name`, readOnly)} />
        <label for="port-start-${entry.id}">Start</label>
        <input id="port-start-${entry.id}" type="number" min="0" max="65535"
          .value=${String(this.persistentValue(`${base}.start`, port.start))}
          .readOnly=${this.originReadOnly(`${base}.start`, readOnly)} />
        <label for="port-end-${entry.id}">End</label>
        <input id="port-end-${entry.id}" type="number" min="0" max="65535"
          .value=${String(this.persistentValue(`${base}.end`, port.end))}
          .readOnly=${this.originReadOnly(`${base}.end`, readOnly)} />
      </div>
      ${this.renderObjectUsage(port)}
    `;
  }

  private renderProtocolEditor(entry: DrawerEntry) {
    const protocol = this.snapshot?.protocols.find(item => item.id === entry.id);
    if (!protocol) return nothing;
    const index = this.snapshot?.protocols.findIndex(item => item.id === entry.id) ?? -1;
    const base = `proto_objects.[${index}]`;
    const readOnly = this.snapshot?.source === 'live' && !this.draftAvailable;
    return html`
      <div class="form-grid">
        <label for="protocol-name-${entry.id}">Name</label>
        <input id="protocol-name-${entry.id}" .value=${this.persistentValue(`${base}.name`, protocol.name)}
          .readOnly=${this.originReadOnly(`${base}.name`, readOnly)} />
        <label for="protocol-number-${entry.id}">IP protocol number</label>
        <input id="protocol-number-${entry.id}" type="number" min="0" max="255"
          .value=${String(this.persistentValue(`${base}.id`, protocol.number))}
          .readOnly=${this.originReadOnly(`${base}.id`, readOnly)} />
      </div>
      ${this.renderObjectUsage(protocol)}
    `;
  }

  private renderBooleanSelect(
    id: string, value: boolean, disabled: boolean,
    trueLabel = 'Enabled', falseLabel = 'Disabled',
  ) {
    return html`<select id=${id} .value=${String(value)} ?disabled=${disabled}>
      <option value="true">${trueLabel}</option><option value="false">${falseLabel}</option>
    </select>`;
  }

  private renderPassRejectSelect(id: string, value: boolean, disabled: boolean) {
    return html`<select id=${id} .value=${value ? 'pass' : 'reject'} ?disabled=${disabled}>
      <option value="pass">Pass</option><option value="reject">Reject</option>
    </select>`;
  }

  private renderProfileEditor(entry: DrawerEntry) {
    const profile = this.snapshot?.profiles.find(item => item.id === entry.id);
    if (!profile) return nothing;
    const routing = profile.routing;
    const tls = profile.tls;
    const detection = profile.detection;
    const content = profile.content;
    const ssh = profile.ssh;
    const dns = profile.dns;
    const script = profile.script;
    const authentication = profile.authentication;
    const mapped = Boolean(routing || tls || detection || content || ssh || dns || script || authentication);
    const mappedReadOnly = this.snapshot?.source === 'live' && !this.draftAvailable;
    const prefix = this.originPrefix(entry);
    const persistent = <T extends ConfigScalar>(field: string, fallback: T): T =>
      prefix ? this.persistentValue(`${prefix}${field}`, fallback) : fallback;
    const persistentStrings = (field: string, fallback: ReadonlyArray<string>): ReadonlyArray<string> =>
      prefix ? this.persistentListValue(`${prefix}${field}`, fallback, 'string') : fallback;
    const persistentNumbers = (field: string, fallback: ReadonlyArray<number>): ReadonlyArray<number> =>
      prefix ? this.persistentListValue(`${prefix}${field}`, fallback, 'number') : fallback;
    const routingAddressValues = routing
      ? persistentStrings('dnat_address', routing.destinationAddresses)
      : [];
    const routingPortValues = routing
      ? persistentStrings('dnat_port', routing.destinationPorts)
      : [];
    const fieldReadOnly = (field: string): boolean =>
      prefix ? this.originReadOnly(`${prefix}${field}`, mappedReadOnly) : mappedReadOnly;
    const booleanSelect = (
      id: string, field: string, value: boolean,
      trueLabel = 'Enabled', falseLabel = 'Disabled',
    ) => this.renderBooleanSelect(
      id, persistent(field, value), fieldReadOnly(field), trueLabel, falseLabel,
    );
    const passRejectSelect = (id: string, field: string, value: boolean) =>
      this.renderPassRejectSelect(id, persistent(field, value), fieldReadOnly(field));
    const configuredScriptType = script?.runtime === 'python' ? '0' : script?.runtime === 'go' ? '1' : '-1';
    const persistentScriptType = persistent('type', configuredScriptType);
    const scriptRuntime = persistentScriptType === '0' ? 'python' : persistentScriptType === '1' ? 'go' : 'unknown';
    return html`
      <div class=${tls || content || ssh ? 'form-grid wide-form-grid' : 'form-grid'}>
        <label for=${mapped ? `profile-name-${entry.id}` : nothing}>Name</label>
        ${mapped ? html`<input id="profile-name-${entry.id}"
          .value=${persistent('name', profile.name)} .readOnly=${fieldReadOnly('name')} />` : html`<span>${profile.name}</span>`}
        <label>Profile type</label><span class="action">${profile.type}</span>
        ${routing ? html`
          <label for="routing-addresses-${entry.id}">Destination addresses</label>
          <input id="routing-addresses-${entry.id}"
            .value=${routingAddressValues.join(', ')} data-reference-preview="true"
            .readOnly=${fieldReadOnly('dnat_address')} />
          <label>Address object links</label>
          <div class="reference-stack">${routingAddressValues.length === 0
            ? html`<span>None</span>`
            : this.renderAddressReferences(entry, `routing-addresses-${entry.id}`, routingAddressValues)}</div>
          <label for="routing-ports-${entry.id}">Destination ports</label>
          <input id="routing-ports-${entry.id}"
            .value=${routingPortValues.join(', ')} data-reference-preview="true"
            .readOnly=${fieldReadOnly('dnat_port')} />
          <label>Port object links</label>
          ${routingPortValues.length === 0
            ? html`<span>None</span>`
            : this.renderPortReferences(entry, `routing-ports-${entry.id}`, routingPortValues)}
          <label for="routing-load-balancing-${entry.id}">Load balancing</label>
          <select id="routing-load-balancing-${entry.id}"
            .value=${persistent('dnat_lb_method', routing.loadBalancingMethod)}
            ?disabled=${fieldReadOnly('dnat_lb_method')}>
            <option value="round-robin">Round robin</option>
            <option value="sticky-l3">Sticky L3</option>
            <option value="sticky-l4">Sticky L4</option>
          </select>
          <label for="routing-rewrite-sni-${entry.id}">Rewrite SNI match</label>
          <input id="routing-rewrite-sni-${entry.id}"
            .value=${persistent('rewrite_sni', routing.rewriteSni)}
            .readOnly=${fieldReadOnly('rewrite_sni')} placeholder="Disabled" />
          <label for="routing-rewrite-sni-to-${entry.id}">Rewrite SNI target</label>
          <input id="routing-rewrite-sni-to-${entry.id}"
            .value=${persistent('rewrite_sni_to', routing.rewriteSniTo)}
            .readOnly=${fieldReadOnly('rewrite_sni_to')} placeholder="Disabled" />
        ` : tls ? html`
          <label for="tls-inspect-${entry.id}">Inspection</label>
          ${booleanSelect(`tls-inspect-${entry.id}`, 'inspect', tls.inspect)}
          <label for="tls-use-pfs-${entry.id}">Perfect forward secrecy</label>
          ${booleanSelect(`tls-use-pfs-${entry.id}`, 'use_pfs', tls.usePfs)}
          <label for="tls-left-use-pfs-${entry.id}">Downstream PFS</label>
          ${booleanSelect(`tls-left-use-pfs-${entry.id}`, 'left_use_pfs', tls.leftUsePfs)}
          <label for="tls-right-use-pfs-${entry.id}">Upstream PFS</label>
          ${booleanSelect(`tls-right-use-pfs-${entry.id}`, 'right_use_pfs', tls.rightUsePfs)}
          <label for="tls-left-disable-reuse-${entry.id}">Downstream session reuse</label>
          ${booleanSelect(`tls-left-disable-reuse-${entry.id}`, 'left_disable_reuse', tls.leftDisableReuse, 'Disabled', 'Allowed')}
          <label for="tls-right-disable-reuse-${entry.id}">Upstream session reuse</label>
          ${booleanSelect(`tls-right-disable-reuse-${entry.id}`, 'right_disable_reuse', tls.rightDisableReuse, 'Disabled', 'Allowed')}
          <label for="tls-allow-untrusted-${entry.id}">Allow untrusted issuers</label>
          ${booleanSelect(`tls-allow-untrusted-${entry.id}`, 'allow_untrusted_issuers', tls.allowUntrustedIssuers, 'Allowed', 'Rejected')}
          <label for="tls-allow-invalid-${entry.id}">Allow invalid certificates</label>
          ${booleanSelect(`tls-allow-invalid-${entry.id}`, 'allow_invalid_certs', tls.allowInvalidCertificates, 'Allowed', 'Rejected')}
          <label for="tls-allow-self-signed-${entry.id}">Allow self-signed certificates</label>
          ${booleanSelect(`tls-allow-self-signed-${entry.id}`, 'allow_self_signed', tls.allowSelfSigned, 'Allowed', 'Rejected')}
          <label for="tls-certificate-transparency-${entry.id}">Certificate transparency</label>
          ${booleanSelect(`tls-certificate-transparency-${entry.id}`, 'ct_enable', tls.certificateTransparency)}
          <label for="tls-ocsp-mode-${entry.id}">OCSP certificate checks</label>
          <select id="tls-ocsp-mode-${entry.id}" .value=${String(persistent('ocsp_mode', tls.ocspMode))}
            ?disabled=${fieldReadOnly('ocsp_mode')}>
            <option value="0">Disabled</option><option value="1">Leaf certificate</option>
            <option value="2">Full chain</option>
          </select>
          <label for="tls-ocsp-stapling-${entry.id}">OCSP stapling</label>
          ${booleanSelect(`tls-ocsp-stapling-${entry.id}`, 'ocsp_stapling', tls.ocspStapling)}
          <label for="tls-ocsp-stapling-mode-${entry.id}">OCSP stapling policy</label>
          <select id="tls-ocsp-stapling-mode-${entry.id}"
            .value=${String(persistent('ocsp_stapling_mode', tls.ocspStaplingMode))}
            ?disabled=${fieldReadOnly('ocsp_stapling_mode')}>
            <option value="0">Loose</option><option value="1">Strict</option><option value="2">Required</option>
          </select>
          <label for="tls-block-alpn-${entry.id}">ALPN negotiation</label>
          ${booleanSelect(`tls-block-alpn-${entry.id}`, 'alpn_block', tls.blockAlpn, 'Blocked', 'Allowed')}
          <label for="tls-sni-cert-${entry.id}">SNI certificate lookup</label>
          ${booleanSelect(`tls-sni-cert-${entry.id}`, 'sni_based_cert', tls.sniBasedCertificates)}
          <label for="tls-ip-cert-${entry.id}">IP certificate lookup</label>
          ${booleanSelect(`tls-ip-cert-${entry.id}`, 'ip_based_cert', tls.ipBasedCertificates)}
          <label for="tls-custom-only-${entry.id}">Custom certificates only</label>
          ${booleanSelect(`tls-custom-only-${entry.id}`, 'only_custom_certs', tls.onlyCustomCertificates, 'Required', 'Not required')}
          <label for="tls-no-fallback-${entry.id}">Fallback bypass</label>
          ${booleanSelect(`tls-no-fallback-${entry.id}`, 'no_fallback_bypass', tls.noFallbackBypass, 'Blocked', 'Allowed')}
          <label for="tls-sni-dns-cache-${entry.id}">SNI filter DNS cache</label>
          ${booleanSelect(`tls-sni-dns-cache-${entry.id}`, 'sni_filter_use_dns_cache', tls.sniFilterUsesDnsCache)}
          <label for="tls-sni-dns-tree-${entry.id}">SNI filter DNS tree</label>
          ${booleanSelect(`tls-sni-dns-tree-${entry.id}`, 'sni_filter_use_dns_domain_tree', tls.sniFilterUsesDnsDomainTree)}
          <label for="tls-warning-ports-${entry.id}">Certificate warning ports</label>
          <input id="tls-warning-ports-${entry.id}"
            .value=${persistentNumbers('redirect_warning_ports', tls.redirectWarningPorts).join(', ')}
            .readOnly=${fieldReadOnly('redirect_warning_ports')} placeholder="443, 44443" />
          <label for="tls-failed-replacement-${entry.id}">Certificate failure replacement</label>
          ${booleanSelect(`tls-failed-replacement-${entry.id}`, 'failed_certcheck_replacement', tls.failedCertificateReplacement)}
          <label for="tls-failed-override-${entry.id}">Certificate failure override</label>
          ${booleanSelect(`tls-failed-override-${entry.id}`, 'failed_certcheck_override', tls.failedCertificateOverride)}
          <label for="tls-failed-override-timeout-${entry.id}">Override timeout</label>
          <input id="tls-failed-override-timeout-${entry.id}" type="number" min="1" max="2147483647"
            .value=${String(persistent('failed_certcheck_override_timeout', tls.failedCertificateOverrideTimeout))}
            .readOnly=${fieldReadOnly('failed_certcheck_override_timeout')} />
          <label for="tls-failed-override-timeout-type-${entry.id}">Override timeout behavior</label>
          <select id="tls-failed-override-timeout-type-${entry.id}"
            .value=${String(persistent('failed_certcheck_override_timeout_type', tls.failedCertificateOverrideTimeoutType))}
            ?disabled=${fieldReadOnly('failed_certcheck_override_timeout_type')}>
            <option value="0">Absolute expiry</option><option value="1">Idle expiry</option>
          </select>
          <label for="tls-key-log-${entry.id}">SSL key logging</label>
          ${booleanSelect(`tls-key-log-${entry.id}`, 'sslkeylog', tls.sslKeyLog)}
          <label for="tls-hello-timeout-${entry.id}">Client hello timeout</label>
          <input id="tls-hello-timeout-${entry.id}" type="number" min="1" max="2147483647"
            .value=${String(persistent('client_hello_timeout', tls.clientHelloTimeoutMs))}
            .readOnly=${fieldReadOnly('client_hello_timeout')} />
          <label for="tls-handshake-timeout-${entry.id}">Handshake timeout</label>
          <input id="tls-handshake-timeout-${entry.id}" type="number" min="1" max="2147483647"
            .value=${String(persistent('handshake_timeout', tls.handshakeTimeoutMs))}
            .readOnly=${fieldReadOnly('handshake_timeout')} />
          <label for="tls-client-action-${entry.id}">Client certificate action</label>
          <select id="tls-client-action-${entry.id}" .value=${persistent('client_cert_action', tls.clientCertificateAction)}
            ?disabled=${fieldReadOnly('client_cert_action')}>
            <option value="block_or_replacement">Block or replacement</option>
            <option value="empty_client_cert">Empty client certificate</option>
            <option value="tls_bypass">TLS bypass</option>
            <option value="use_configured">Use configured certificate</option>
          </select>
          <label for="tls-alerts-${entry.id}">Alerts</label>
          <select id="tls-alerts-${entry.id}" .value=${persistent('alerts', tls.alerts)}
            ?disabled=${fieldReadOnly('alerts')}>
            <option value="all">All</option><option value="unusual">Unusual</option><option value="mute">Mute</option>
          </select>
          <label for="tls-write-sni-${entry.id}-mode">SNI bypass list</label>
          <div class="write-only-control">
            <select id="tls-write-sni-${entry.id}-mode" ?disabled=${mappedReadOnly}>
              <option value="unchanged">Keep ${tls.sniBypassEntries} configured entries</option>
              <option value="replace">Replace</option><option value="clear">Clear</option>
            </select>
            <textarea id="tls-write-sni-${entry.id}-value" aria-label="SNI bypass list replacement"
              placeholder='["private.example"] (write-only)' autocomplete="off"
              .readOnly=${mappedReadOnly}></textarea>
          </div>
        ` : detection ? html`
          <label for="detection-mode-${entry.id}">Detection phase</label>
          <select id="detection-mode-${entry.id}" .value=${String(persistent('mode', detection.mode))}
            ?disabled=${fieldReadOnly('mode')}>
            <option value="0">Disabled</option><option value="1">Pre-read</option><option value="2">Post-read</option>
          </select>
          <label for="detection-engines-${entry.id}">L7 engines</label>
          <select id="detection-engines-${entry.id}"
            .value=${String(persistent('engines_enabled', detection.enginesEnabled))}
            ?disabled=${fieldReadOnly('engines_enabled')}>
            <option value="true">Enabled</option><option value="false">Disabled</option>
          </select>
          <label for="detection-kb-${entry.id}">Knowledge base</label>
          <select id="detection-kb-${entry.id}"
            .value=${String(persistent('kb_enabled', detection.knowledgeBaseEnabled))}
            ?disabled=${fieldReadOnly('kb_enabled')}>
            <option value="true">Enabled</option><option value="false">Disabled</option>
          </select>
        ` : content ? html`
          <label for="content-write-payload-${entry.id}">Payload capture</label>
          ${booleanSelect(`content-write-payload-${entry.id}`, 'write_payload', content.writePayload)}
          <label for="content-format-${entry.id}">Capture format</label>
          <select id="content-format-${entry.id}" .value=${persistent('write_format', content.writeFormat)}
            ?disabled=${fieldReadOnly('write_format')}>
            <option value="smcap">SMCAP</option><option value="pcap">PCAP</option>
            <option value="pcap_single">Single PCAP</option>
          </select>
          <label for="content-webhook-${entry.id}">Webhook</label>
          ${booleanSelect(`content-webhook-${entry.id}`, 'webhook_enable', content.webhookEnabled)}
          <label for="content-webhook-lock-${entry.id}">Webhook traffic lock</label>
          ${booleanSelect(`content-webhook-lock-${entry.id}`, 'webhook_lock_traffic', content.webhookLocksTraffic)}
          <label for="content-ja4-client-${entry.id}">JA4 TLS ClientHello</label>
          ${booleanSelect(`content-ja4-client-${entry.id}`, 'ja4_tls_ch', content.ja4TlsClientHello)}
          <label for="content-ja4-ignore-sni-${entry.id}">JA4 ignores SNI</label>
          ${booleanSelect(`content-ja4-ignore-sni-${entry.id}`, 'ja4_tls_ch_ignore_sni', content.ja4TlsClientHelloIgnoresSni, 'Yes', 'No')}
          <label for="content-ja4-server-${entry.id}">JA4 TLS ServerHello</label>
          ${booleanSelect(`content-ja4-server-${entry.id}`, 'ja4_tls_sh', content.ja4TlsServerHello)}
          <label for="content-ja4-http-${entry.id}">JA4 HTTP</label>
          ${booleanSelect(`content-ja4-http-${entry.id}`, 'ja4_http', content.ja4Http)}
          <label for="content-write-filter-${entry.id}-mode">Session filter</label>
          <div class="write-only-control">
            <select id="content-write-filter-${entry.id}-mode" ?disabled=${mappedReadOnly}>
              <option value="unchanged">${content.sessionFilterConfigured ? 'Keep configured filter' : 'Keep empty'}</option>
              <option value="replace">Replace</option><option value="clear">Clear</option>
            </select>
            <textarea id="content-write-filter-${entry.id}-value" aria-label="Session filter replacement"
              placeholder="New expression (write-only)" autocomplete="off"
              .readOnly=${mappedReadOnly}></textarea>
          </div>
          <label>Content rules</label>
          <div class="reference-stack" role="group" aria-label="Content rules">
            ${content.rules.length === 0 ? html`<span>No content rules configured.</span>` :
              content.rules.map((rule, index) => html`
                <button class="reference" type="button"
                  @click=${(event: MouseEvent) => this.openContentRule(
                    rule.id, event.currentTarget as HTMLElement,
                  )}>
                  <span><strong>Rule ${index + 1}</strong> · match configured ·
                    ${rule.replacementConfigured
                      ? rule.replacementHasValue ? 'replacement configured' : 'empty replacement'
                      : 'no replacement'} · ${rule.fillLength ? 'length preserved' : 'length may change'} ·
                    ${rule.replaceEachNth <= 1 ? 'every match' : `every ${rule.replaceEachNth}th match`}</span>
                  <span aria-hidden="true">→</span>
                </button>
              `)}
          </div>
        ` : ssh ? html`
          <label for="ssh-write-host-key-${entry.id}-mode">Host key</label>
          <div class="write-only-control">
            <select id="ssh-write-host-key-${entry.id}-mode" ?disabled=${mappedReadOnly}>
              <option value="unchanged">${ssh.hostKeyConfigured ? 'Keep configured path' : 'Keep empty'}</option>
              <option value="replace">Replace</option><option value="clear">Clear</option>
            </select>
            <input id="ssh-write-host-key-${entry.id}-value" aria-label="Host key replacement"
              placeholder="New path (write-only)" autocomplete="off" .readOnly=${mappedReadOnly} />
          </div>
          <label for="ssh-host-key-policy-${entry.id}">Upstream host-key policy</label>
          <select id="ssh-host-key-policy-${entry.id}" .value=${persistent('hostkey_policy', ssh.hostKeyPolicy)}
            ?disabled=${fieldReadOnly('hostkey_policy')}>
            <option value="insecure">Insecure</option><option value="accept-new">Accept new</option>
            <option value="strict">Strict</option>
          </select>
          <label for="ssh-shell-${entry.id}">Shell</label>
          ${passRejectSelect(`ssh-shell-${entry.id}`, 'shell', ssh.shell)}
          <label for="ssh-exec-${entry.id}">Exec</label>
          ${passRejectSelect(`ssh-exec-${entry.id}`, 'exec', ssh.exec)}
          <label for="ssh-subsystem-${entry.id}">Subsystem</label>
          ${passRejectSelect(`ssh-subsystem-${entry.id}`, 'subsystem', ssh.subsystem)}
          <label for="ssh-pty-${entry.id}">PTY</label>
          ${passRejectSelect(`ssh-pty-${entry.id}`, 'pty', ssh.pty)}
          <label for="ssh-environment-${entry.id}">Environment</label>
          ${passRejectSelect(`ssh-environment-${entry.id}`, 'environment', ssh.environment)}
          <label for="ssh-local-forward-${entry.id}">Local forwarding</label>
          ${passRejectSelect(`ssh-local-forward-${entry.id}`, 'local_forward', ssh.localForward)}
          <label for="ssh-remote-forward-${entry.id}">Remote forwarding</label>
          ${passRejectSelect(`ssh-remote-forward-${entry.id}`, 'remote_forward', ssh.remoteForward)}
          <label for="ssh-x11-${entry.id}">X11 forwarding</label>
          ${passRejectSelect(`ssh-x11-${entry.id}`, 'x11', ssh.x11)}
          <label for="ssh-agent-${entry.id}">Agent forwarding</label>
          ${passRejectSelect(`ssh-agent-${entry.id}`, 'agent', ssh.agent)}
        ` : dns ? html`
          <label for="dns-match-${entry.id}">Match request ID</label>
          <select id="dns-match-${entry.id}" .value=${String(persistent('match_request_id', dns.matchRequestId))}
            ?disabled=${fieldReadOnly('match_request_id')}>
            <option value="true">Enabled</option><option value="false">Disabled</option>
          </select>
          <label for="dns-randomize-${entry.id}">Randomize upstream ID</label>
          <select id="dns-randomize-${entry.id}" .value=${String(persistent('randomize_id', dns.randomizeId))}
            ?disabled=${fieldReadOnly('randomize_id')}>
            <option value="true">Enabled</option><option value="false">Disabled</option>
          </select>
          <label for="dns-cached-${entry.id}">Cached responses</label>
          <select id="dns-cached-${entry.id}" .value=${String(persistent('cached_responses', dns.cachedResponses))}
            ?disabled=${fieldReadOnly('cached_responses')}>
            <option value="true">Enabled</option><option value="false">Disabled</option>
          </select>
        ` : script ? html`
          <label for="script-runtime-${entry.id}">Runtime</label>
          <select id="script-runtime-${entry.id}" .value=${scriptRuntime} ?disabled=${fieldReadOnly('type')}>
            <option value="python">Python</option><option value="go">Go</option>
            <option value="unknown">Unspecified</option>
          </select>
          <label for="script-write-module-${entry.id}-mode">Module path</label>
          <div class="write-only-control">
            <select id="script-write-module-${entry.id}-mode" ?disabled=${mappedReadOnly}>
              <option value="unchanged">${script.modulePathConfigured ? 'Keep configured path' : 'Keep empty'}</option>
              <option value="replace">Replace</option><option value="clear">Clear</option>
            </select>
            <input id="script-write-module-${entry.id}-value" aria-label="Module path replacement"
              placeholder="New path (write-only)" autocomplete="off" .readOnly=${mappedReadOnly} />
          </div>
        ` : authentication ? html`
          <label>Lifecycle</label><span>Deprecated compatibility profile</span>
          <label for="auth-authenticate-${entry.id}">Authenticate</label>
          ${booleanSelect(`auth-authenticate-${entry.id}`, 'authenticate', authentication.authenticate)}
          <label for="auth-resolve-${entry.id}">Resolve identities</label>
          ${booleanSelect(`auth-resolve-${entry.id}`, 'resolve', authentication.resolve)}
          <label>Identity mappings</label><span>${authentication.identityCount} redacted entries · unchanged</span>
        ` : html`<label>Value exposure</label><span>Metadata only</span>`}
      </div>
      ${routing || tls || detection || content || ssh || dns || script || authentication ? nothing : html`<div class="privacy-note section">
        Profile values remain inside the GUI core until a typed, redacted editor is available.
      </div>`}
      ${tls ? html`<div class="privacy-note section">
        Current SNI bypass values stay inside the GUI core; replacements are write-only.
      </div>` : nothing}
      ${content ? html`<div class="privacy-note section">
        Current session filters and all content-rule payloads stay inside the GUI core. Filter replacements are write-only.
      </div>` : nothing}
      ${ssh ? html`<div class="privacy-note section">
        The current private host-key path stays inside the GUI core. Replacements are write-only.
      </div>` : nothing}
      ${script ? html`<div class="privacy-note section">
        The current script module path stays inside the GUI core. Replacements are write-only.
      </div>` : nothing}
      ${authentication ? html`<div class="privacy-note section">
        Authentication profiles are obsolete in Smithproxy; identity names and profile bindings stay inside the GUI core.
      </div>` : nothing}
      ${this.renderObjectUsage(profile)}
    `;
  }

  private renderSystemSettingsEditor() {
    const settings = this.snapshot?.settings;
    if (!settings) return nothing;
    const disabled = this.snapshot?.source === 'live' && !this.draftAvailable;
    const booleanPaths: ReadonlyMap<string, string> = new Map(
      systemBooleanFields.map(([path, id]) => [id, `settings.${path}`]),
    );
    const workerPaths: ReadonlyMap<string, string> = new Map(
      systemWorkerFields.map(([path, id]) => [id, `settings.${path}`]),
    );
    const numericPaths: ReadonlyMap<string, string> = new Map([
      ...systemNumericFields.map(([path, id]) => [id, `settings.${path}`] as const),
      ['api-key-timeout', 'settings.http_api.key_timeout'],
      ['webhook-sift-payload-limit', 'settings.webhook.sift_payload_limit_per_direction'],
    ]);
    const tuningPaths: ReadonlyMap<string, string> = new Map(
      systemTuningFields.map(([path, id]) => [id, `settings.tuning.${path}`]),
    );
    const scalar = <T extends ConfigScalar>(path: string, fallback: T): T => this.persistentValue(path, fallback);
    const strings = (path: string, fallback: ReadonlyArray<string>): ReadonlyArray<string> =>
      this.persistentListValue(path, fallback, 'string');
    const locked = (path: string): boolean => this.originReadOnly(path, disabled);
    const booleanField = (id: string, label: string, value: boolean) => html`
      <label for="settings-${id}">${label}</label>
      ${this.renderBooleanSelect(
        `settings-${id}`, scalar(booleanPaths.get(id)!, value), locked(booleanPaths.get(id)!),
      )}
    `;
    const workerField = (id: string, label: string, value: number) => html`
      <label for="settings-worker-${id}">${label}</label>
      <input id="settings-worker-${id}" type="number" min="-1" max="4096"
        .value=${String(scalar(workerPaths.get(id)!, value))} .readOnly=${locked(workerPaths.get(id)!)} />
    `;
    const numericField = (id: string, label: string, value: number, maximum: number) => html`
      <label for="settings-${id}">${label}</label>
      <input id="settings-${id}" type="number" min="0" max=${String(maximum)}
        .value=${String(scalar(numericPaths.get(id)!, value))} .readOnly=${locked(numericPaths.get(id)!)} />
    `;
    const tuningField = (id: string, label: string, value: number, minimum: number, maximum: number) => html`
      <label for="settings-tuning-${id}">${label}</label>
      <input id="settings-tuning-${id}" type="number" min=${String(minimum)} max=${String(maximum)}
        .value=${String(scalar(tuningPaths.get(id)!, value))} .readOnly=${locked(tuningPaths.get(id)!)} />
    `;
    const writeOnlyField = (
      id: string, label: string, configured: boolean, secret = false,
    ) => html`
      <label for="settings-write-${id}-mode">${label}</label>
      <div class="write-only-control">
        <select id="settings-write-${id}-mode" ?disabled=${disabled}>
          <option value="unchanged">${configured ? 'Keep configured value' : 'Keep empty'}</option>
          <option value="replace">Replace</option>
          <option value="clear">Clear</option>
        </select>
        <input id="settings-write-${id}-value" type=${secret ? 'password' : 'text'}
          aria-label="${label} replacement" placeholder="New value (write-only)"
          autocomplete=${secret ? 'new-password' : 'off'} .readOnly=${disabled} />
      </div>
    `;
    return html`
      <div class="form-grid wide-form-grid">
        ${booleanField('accept-tproxy', 'TPROXY listener', settings.acceptTproxy)}
        ${booleanField('accept-redirect', 'REDIRECT listener', settings.acceptRedirect)}
        ${booleanField('accept-socks', 'SOCKS listener', settings.acceptSocks)}
        ${booleanField('accept-http-connect', 'HTTP CONNECT listener', settings.acceptHttpConnect)}
        ${booleanField('accept-api', 'Smithproxy API listener', settings.acceptApi)}
        ${booleanField(
          'extended-local-destination-protection',
          'Protect local explicit-proxy destinations',
          settings.extendedLocalDestinationProtection,
        )}
        ${booleanField('policy-fail-open', 'Policy failure', settings.policyFailOpen)}
        ${booleanField('access-fail-open', 'Access request failure', settings.accessRequestFailOpen)}
        ${workerField('plaintext', 'Plaintext workers', settings.workers.plaintext)}
        ${workerField('tls', 'TLS workers', settings.workers.tls)}
        ${workerField('udp', 'UDP workers', settings.workers.udp)}
        ${workerField('dtls', 'DTLS workers', settings.workers.dtls)}
        ${workerField('quic', 'QUIC workers', settings.workers.quic)}
        ${workerField('socks', 'SOCKS workers', settings.workers.socks)}
        ${workerField('http-connect', 'HTTP CONNECT workers', settings.workers.httpConnect)}
        <span class="form-span privacy-note">Use -1 to disable a listener; 0 lets Smithproxy choose its default worker count.</span>
        <h3 class="form-span">Listener endpoints</h3>
        ${numericField('port-plaintext', 'Plaintext port', settings.ports.plaintext, 65535)}
        ${numericField('port-tls', 'TLS port', settings.ports.tls, 65535)}
        ${numericField('port-udp', 'UDP port', settings.ports.udp, 65535)}
        ${numericField('port-dtls', 'DTLS port', settings.ports.dtls, 65535)}
        ${numericField('port-quic', 'QUIC port', settings.ports.quic, 65535)}
        ${numericField('port-socks', 'SOCKS port', settings.ports.socks, 65535)}
        ${numericField('port-http-connect', 'HTTP CONNECT port', settings.ports.httpConnect, 65535)}
        ${numericField('ocsp-status-ttl', 'OCSP status TTL (seconds)', settings.ocspStatusTtl, 31536000)}
        ${numericField('crl-status-ttl', 'CRL status TTL (seconds)', settings.crlStatusTtl, 31536000)}
        <h3 class="form-span">Logging and payloads</h3>
        ${booleanField('logging-default-payload', 'Default payload capture', settings.logging.defaultWritePayload)}
        ${numericField('logging-pcap-quota', 'Single PCAP quota', settings.logging.pcapSingleQuota, 1048576)}
        ${numericField('logging-level', 'Log level', settings.logging.level, 10)}
        ${booleanField('logging-console', 'Console logging', settings.logging.console)}
        ${numericField('logging-syslog-port', 'Syslog port', settings.logging.syslogPort, 65535)}
        ${numericField('logging-syslog-facility', 'Syslog facility', settings.logging.syslogFacility, 23)}
        ${numericField('logging-syslog-level', 'Syslog level', settings.logging.syslogLevel, 10)}
        <label for="settings-logging-syslog-family">Syslog address family</label>
        <select id="settings-logging-syslog-family"
          .value=${String(scalar('settings.syslog_family', settings.logging.syslogFamily))}
          ?disabled=${locked('settings.syslog_family')}>
          <option value="4">IPv4</option><option value="6">IPv6</option>
        </select>
        ${writeOnlyField('payload-directory', 'Payload directory', settings.logging.payloadDirectoryConfigured)}
        ${writeOnlyField('log-file', 'Log file', settings.logging.fileConfigured)}
        ${writeOnlyField('tls-key-log-file', 'TLS key log file', settings.logging.sslKeyFileConfigured)}
        ${writeOnlyField('syslog-server', 'Syslog server', settings.logging.syslogServerConfigured)}
        <h3 class="form-span">Auxiliary services</h3>
        ${numericField('aux-cli-port', 'CLI port', settings.auxiliary.cliPort, 65535)}
        ${booleanField('aux-thread-pool-log', 'Thread-pool task logging', settings.auxiliary.threadPoolLogging)}
        ${booleanField('aux-socks-async-dns', 'SOCKS asynchronous DNS', settings.auxiliary.socksAsyncDns)}
        ${booleanField('aux-socks-ipver-mixing', 'SOCKS IP-version mixing', settings.auxiliary.socksIpVersionMixing)}
        ${booleanField('aux-socks-prefer-ipv6', 'SOCKS prefer IPv6', settings.auxiliary.socksPreferIpv6)}
        ${writeOnlyField('cli-password', 'CLI password', settings.auxiliary.cliPasswordConfigured, true)}
        <label for="settings-udp-quick-ports">UDP quick ports</label>
        <input id="settings-udp-quick-ports"
          .value=${strings('settings.udp_quick_ports', settings.auxiliary.udpQuickPorts).join(', ')}
          placeholder="0, 53, 443" .readOnly=${locked('settings.udp_quick_ports')} />
        ${writeOnlyField('certificates-path', 'Certificates path', settings.auxiliary.certificatesPathConfigured)}
        ${writeOnlyField('certificate-password', 'Certificate password', settings.auxiliary.certificatePasswordConfigured, true)}
        ${writeOnlyField('certificate-transparency-log', 'Certificate transparency log file', settings.auxiliary.certificateTransparencyLogConfigured)}
        ${writeOnlyField('ca-bundle-path', 'CA bundle path', settings.auxiliary.caBundlePathConfigured)}
        ${writeOnlyField('ca-bundle-file', 'CA bundle file', settings.auxiliary.caBundleFileConfigured)}
        ${writeOnlyField('admin-group', 'Administration group', settings.auxiliary.adminGroupConfigured)}
        ${writeOnlyField('messages-directory', 'Message assets', settings.auxiliary.messagesDirectoryConfigured)}
        ${writeOnlyField('payload-prefix', 'Payload filename prefix', settings.auxiliary.payloadFilePrefixConfigured)}
        ${writeOnlyField('payload-suffix', 'Payload filename suffix', settings.auxiliary.payloadFileSuffixConfigured)}
        ${writeOnlyField('web-rating-key', 'Web rating key', settings.auxiliary.webRatingKeyConfigured, true)}
        <h3 class="form-span">Performance tuning</h3>
        ${tuningField('host-buffer-min', 'Initial host buffer (bytes)', settings.auxiliary.tuning.hostBufferMin, 1500, 10000000)}
        ${tuningField('host-buffer-max-multiplier', 'Maximum buffer multiplier', settings.auxiliary.tuning.hostBufferMaxMultiplier, 1, 1024000000)}
        ${tuningField('host-write-full', 'Queued write threshold (bytes)', settings.auxiliary.tuning.hostWriteFull, 1024, 1024000000)}
        ${tuningField('host-io-batch', 'Host I/O batch (bytes)', settings.auxiliary.tuning.hostIoBatch, 16384, 16777216)}
        ${tuningField('tls-write-chunk', 'TLS write chunk (bytes)', settings.auxiliary.tuning.tlsWriteChunk, 1024, 1048576)}
        ${tuningField('host-open-timeout', 'Host open timeout (seconds)', settings.auxiliary.tuning.hostOpenTimeout, 0, 65535)}
        ${tuningField('host-idle-timeout', 'Host idle timeout (seconds)', settings.auxiliary.tuning.hostIdleTimeout, 0, 65535)}
        ${tuningField('neighbor-cache-size', 'Neighbor cache entries', settings.auxiliary.tuning.neighborCacheSize, 1, 2147483647)}
        ${booleanField('tls-autodetect', 'TLS autodetection', settings.tlsAutodetect)}
        ${booleanField('tls-autodetect-harder', 'Aggressive TLS autodetection', settings.tlsAutodetectHarder)}
        ${booleanField('kernel-tls', 'Kernel TLS', settings.kernelTls)}
        <h3 class="form-span">Smithproxy HTTP API</h3>
        ${numericField('api-key-timeout', 'API token TTL (seconds)', settings.httpApi.keyTimeout, 4294967295)}
        <label for="settings-api-port">API port</label>
        <input id="settings-api-port" type="number" min="1025" max="65534"
          .value=${String(scalar('settings.http_api.port', settings.httpApi.port))}
          .readOnly=${locked('settings.http_api.port')} />
        ${booleanField('api-key-extend', 'Refresh tokens on access', settings.httpApi.keyExtendOnAccess)}
        ${booleanField('api-loopback', 'API loopback only', settings.httpApi.loopbackOnly)}
        ${booleanField('api-pam', 'API PAM login', settings.httpApi.pamLogin)}
        ${booleanField('api-header', 'API header access', settings.httpApi.allowApiHeader)}
        ${writeOnlyField('api-bind-address', 'API bind address', settings.httpApi.bindAddressConfigured)}
        ${writeOnlyField('api-bind-interface', 'API bind interface', settings.httpApi.bindInterfaceConfigured)}
        <h3 class="form-span">Webhook</h3>
        ${booleanField('webhook-enabled', 'Webhook', settings.webhook.enabled)}
        ${booleanField('webhook-tls', 'Webhook TLS verification', settings.webhook.tlsVerify)}
        ${booleanField('webhook-sift', 'Webhook Sift', settings.webhook.siftEnabled)}
        ${booleanField('webhook-override', 'Webhook API override', settings.webhook.apiOverride)}
        <label for="settings-webhook-sift-lored-mode">Sift LoreD enrichment</label>
        <select id="settings-webhook-sift-lored-mode"
          .value=${scalar('settings.webhook.sift_lored_mode', settings.webhook.siftLoredMode)}
          ?disabled=${locked('settings.webhook.sift_lored_mode')}>
          <option value="disabled">Disabled</option>
          <option value="optional">Optional</option>
          <option value="required">Required</option>
        </select>
        ${booleanField(
          'webhook-sift-lored-include-url',
          'Allow LoreD URL disclosure',
          settings.webhook.siftLoredIncludeUrl,
        )}
        ${numericField('webhook-sift-payload-limit', 'Sift payload limit per direction', settings.webhook.siftPayloadLimitPerDirection, 1073741824)}
        ${numericField('webhook-ping-interval', 'Webhook ping interval (seconds)', settings.webhook.pingInterval, 2147483647)}
        ${numericField('webhook-neighbor-update-interval', 'Neighbor update interval (seconds)', settings.webhook.neighborUpdateInterval, 2147483647)}
        ${numericField('webhook-neighbor-tag-refresh-age', 'Neighbor tag refresh age (seconds)', settings.webhook.neighborTagRefreshAge, 2147483647)}
        ${booleanField('webhook-task-debug', 'Webhook task diagnostics', settings.webhook.taskDebug)}
        ${booleanField('webhook-task-debug-dump', 'Webhook task dump diagnostics', settings.webhook.taskDebugDump)}
        <label for="settings-nameservers">Nameservers</label>
        <input id="settings-nameservers"
          .value=${strings('settings.nameservers', settings.nameservers).join(', ')}
          placeholder="192.0.2.53, resolver.example" .readOnly=${locked('settings.nameservers')} />
        <label for="settings-api-keys-mode">HTTP API keys</label>
        <div class="write-only-control">
          <select id="settings-api-keys-mode" ?disabled=${disabled}>
            <option value="unchanged">Keep ${settings.httpApi.keyCount} configured key${settings.httpApi.keyCount === 1 ? '' : 's'}</option>
            <option value="replace">Replace all</option>
            <option value="clear">Clear all</option>
          </select>
          <input id="settings-api-keys-value" type="password" autocomplete="new-password"
            aria-label="HTTP API keys replacement" placeholder='["new-key", "overlap-key"]'
            .readOnly=${disabled} />
        </div>
        <label for="settings-api-allowed-ips">HTTP API allowed IPs</label>
        <input id="settings-api-allowed-ips"
          .value=${strings('settings.http_api.allowed_ips', settings.httpApi.allowedIps).join(', ')}
          placeholder="127.0.0.1, 192.0.2.0/24"
          .readOnly=${locked('settings.http_api.allowed_ips')} />
        ${writeOnlyField('webhook-url', 'Webhook URL', settings.webhook.urlConfigured)}
        ${writeOnlyField('webhook-sift-url', 'Sift URL', settings.webhook.siftUrlConfigured)}
        ${writeOnlyField('webhook-sift-tenant', 'Sift tenant ID', settings.webhook.siftTenantConfigured)}
        ${writeOnlyField('webhook-sift-instance', 'Sift instance ID', settings.webhook.siftInstanceConfigured)}
        ${writeOnlyField('webhook-host-id', 'Webhook host ID', settings.webhook.hostIdConfigured)}
        ${writeOnlyField('webhook-bind-interface', 'Webhook bind interface', settings.webhook.bindInterfaceConfigured)}
        ${this.snapshot?.debug ? html`
          <h3 class="form-span">Debug logging</h3>
          <label for="debug-data-crc">Payload CRC logging</label>
          ${this.renderBooleanSelect(
            'debug-data-crc', scalar('debug.log_data_crc', this.snapshot.debug.logDataCrc),
            locked('debug.log_data_crc'),
          )}
          <label for="debug-sockets">Socket event logging</label>
          ${this.renderBooleanSelect(
            'debug-sockets', scalar('debug.log_sockets', this.snapshot.debug.logSockets), locked('debug.log_sockets'),
          )}
          <label for="debug-online-name">Resolve online connection names</label>
          ${this.renderBooleanSelect(
            'debug-online-name', scalar('debug.log_online_cx_name', this.snapshot.debug.logOnlineConnectionName),
            locked('debug.log_online_cx_name'),
          )}
          <label for="debug-source-lines">Source lines at diagnostic levels</label>
          ${this.renderBooleanSelect(
            'debug-source-lines', scalar('debug.log_srclines', this.snapshot.debug.logSourceLines),
            locked('debug.log_srclines'),
          )}
          <label for="debug-source-lines-always">Source lines at every level</label>
          ${this.renderBooleanSelect(
            'debug-source-lines-always', scalar('debug.log_srclines_always', this.snapshot.debug.logSourceLinesAlways),
            locked('debug.log_srclines_always'),
          )}
          <h3 class="form-span">Per-module overrides</h3>
          ${this.snapshot.debug.moduleOverrides.map((override, index) => {
            const id = `debug-module-${index}`;
            const label = `${override.name} module override`;
            return html`
              <label for=${id}>${label}</label>
              ${override.kind === 'boolean'
                ? this.renderBooleanSelect(
                    id, scalar(`debug.log.${override.name}`, Boolean(override.value)),
                    locked(`debug.log.${override.name}`),
                  )
                : html`<input id=${id} type=${override.kind === 'integer' ? 'number' : 'text'}
                    min=${override.kind === 'integer' ? '-2147483648' : nothing}
                    max=${override.kind === 'integer' ? '2147483647' : nothing}
                    maxlength=${override.kind === 'string' ? '32' : nothing}
                    .value=${String(scalar(`debug.log.${override.name}`, override.value))}
                    .readOnly=${locked(`debug.log.${override.name}`)} />`}
            `;
          })}
          ${this.snapshot.debug.moduleOverrideCount === 0
            ? html`<span class="form-span">No per-module overrides are configured.</span>`
            : nothing}
        ` : nothing}
      </div>
    `;
  }

  private renderCaptureSettingsEditor() {
    const captures = this.snapshot?.captures;
    if (!captures) return nothing;
    const disabled = this.snapshot?.source === 'live' && !this.draftAvailable;
    const booleanPaths: ReadonlyMap<string, string> = new Map(
      captureBooleanFields.map(([path, id]) => [id, `captures.${path}`]),
    );
    const scalar = <T extends ConfigScalar>(path: string, fallback: T): T => this.persistentValue(path, fallback);
    const locked = (path: string): boolean => this.originReadOnly(path, disabled);
    const booleanField = (id: string, value: boolean) => this.renderBooleanSelect(
      `captures-${id}`, scalar(booleanPaths.get(id)!, value), locked(booleanPaths.get(id)!),
    );
    const writeOnlyField = (id: string, label: string, configured: boolean) => html`
      <label for="captures-write-${id}-mode">${label}</label>
      <div class="write-only-control">
        <select id="captures-write-${id}-mode" ?disabled=${disabled}>
          <option value="unchanged">${configured ? 'Keep configured value' : 'Keep empty'}</option>
          <option value="replace">Replace</option>
          <option value="clear">Clear</option>
        </select>
        <input id="captures-write-${id}-value" aria-label="${label} replacement"
          placeholder="New value (write-only)" autocomplete="off" .readOnly=${disabled} />
      </div>
    `;
    return html`
      <div class="form-grid wide-form-grid">
        <label for="captures-local-enabled">Local capture</label>
        ${booleanField('local-enabled', captures.local.enabled)}
        <label for="captures-local-format">Local format</label>
        <select id="captures-local-format" .value=${scalar('captures.local.format', captures.local.format)}
          ?disabled=${locked('captures.local.format')}>
          <option value="pcap_single">PCAP single</option><option value="pcap">PCAP</option><option value="smcap">SMCAP</option>
        </select>
        <label for="captures-local-quota">Local quota (MiB)</label>
        <input id="captures-local-quota" type="number" min="0" max="1048576"
          .value=${String(scalar('captures.local.pcap_quota', captures.local.quotaMiB))}
          .readOnly=${locked('captures.local.pcap_quota')} />
        ${writeOnlyField('local-directory', 'Local directory', captures.local.directoryConfigured)}
        ${writeOnlyField('local-prefix', 'Local filename prefix', captures.local.filePrefixConfigured)}
        ${writeOnlyField('local-suffix', 'Local filename suffix', captures.local.fileSuffixConfigured)}
        <label for="captures-remote-enabled">Remote capture</label>
        ${booleanField('remote-enabled', captures.remote.enabled)}
        <label for="captures-tunnel-type">Tunnel type</label>
        <select id="captures-tunnel-type"
          .value=${scalar('captures.remote.tun_type', captures.remote.tunnelType)}
          ?disabled=${locked('captures.remote.tun_type')}>
          <option value="gre">GRE</option>
        </select>
        <label for="captures-gre-format">GRE format</label>
        <select id="captures-gre-format" .value=${scalar('captures.remote.gre_format', captures.remote.greFormat)}
          ?disabled=${locked('captures.remote.gre_format')}>
          <option value="traffic">Traffic</option><option value="pcapng">PCAPNG</option>
        </select>
        <label for="captures-remote-ttl">Tunnel TTL</label>
        <input id="captures-remote-ttl" type="number" min="0" max="255"
          .value=${String(scalar('captures.remote.tun_ttl', captures.remote.ttl))}
          .readOnly=${locked('captures.remote.tun_ttl')} />
        ${writeOnlyField('remote-destination', 'Remote destination', captures.remote.destinationConfigured)}
        ${writeOnlyField('bind-interface', 'Bound interface', captures.remote.bindInterfaceConfigured)}
        <label for="captures-checksums">Calculate checksums</label>
        ${booleanField('checksums', captures.calculateChecksums)}
      </div>
    `;
  }

  private renderCertificateAuthorityEditor(entry: DrawerEntry) {
    const authority = this.snapshot?.securityAssets?.certificateAuthorities.find(item => item.id === entry.id);
    if (!authority) return nothing;
    const disabled = this.snapshot?.source === 'live' && !this.draftAvailable;
    const prefix = this.originPrefix(entry);
    const namePath = `${prefix ?? ''}name`;
    return html`
      <div class="form-grid">
        <label for="authority-name-${entry.id}">Name</label>
        <input id="authority-name-${entry.id}" .value=${this.persistentValue(namePath, authority.name)}
          .readOnly=${this.originReadOnly(namePath, disabled)} />
        <label for="authority-write-path-${entry.id}-mode">CA path</label>
        <div class="write-only-control">
          <select id="authority-write-path-${entry.id}-mode" ?disabled=${disabled}>
            <option value="unchanged">${authority.pathConfigured ? 'Keep configured path' : 'Keep empty'}</option>
            <option value="replace">Replace</option><option value="clear">Clear</option>
          </select>
          <input id="authority-write-path-${entry.id}-value" aria-label="CA path replacement"
            placeholder="New absolute path (write-only)" autocomplete="off" .readOnly=${disabled} />
        </div>
      </div>
      <div class="privacy-note section">
        The current certificate-authority path stays inside the GUI core. Replacements are write-only.
      </div>
    `;
  }

  private renderContentRuleEditor(entry: DrawerEntry) {
    const profile = this.snapshot?.profiles.find(item => item.content?.rules.some(rule => rule.id === entry.id));
    const rule = profile?.content?.rules.find(item => item.id === entry.id);
    if (!profile || !rule) return nothing;
    const disabled = this.snapshot?.source === 'live' && !this.draftAvailable;
    const prefix = this.originPrefix(entry);
    const path = (field: string) => `${prefix ?? ''}${field}`;
    return html`
      <div class="form-grid wide-form-grid">
        <label>Content profile</label><span>${profile.name}</span>
        <label for="content-rule-fill-length-${entry.id}">Preserve matched length</label>
        ${this.renderBooleanSelect(
          `content-rule-fill-length-${entry.id}`, this.persistentValue(path('fill_length'), rule.fillLength),
          this.originReadOnly(path('fill_length'), disabled), 'Yes', 'No',
        )}
        <label for="content-rule-replace-each-${entry.id}">Replace every Nth match</label>
        <input id="content-rule-replace-each-${entry.id}" type="number"
          min="-2147483648" max="2147483647"
          .value=${String(this.persistentValue(path('replace_each_nth'), rule.replaceEachNth))}
          .readOnly=${this.originReadOnly(path('replace_each_nth'), disabled)} />
        <label for="content-rule-write-match-${entry.id}-mode">Match expression</label>
        <div class="write-only-control">
          <select id="content-rule-write-match-${entry.id}-mode" ?disabled=${disabled}>
            <option value="unchanged">${rule.matchConfigured ? 'Keep configured match' : 'Keep empty'}</option>
            <option value="replace">Replace</option>
          </select>
          <textarea id="content-rule-write-match-${entry.id}-value" maxlength="65536"
            aria-label="Content match replacement" autocomplete="off"
            placeholder="New match expression (write-only)" .readOnly=${disabled}></textarea>
        </div>
        <label for="content-rule-write-replacement-${entry.id}-mode">Replacement expression</label>
        <div class="write-only-control">
          <select id="content-rule-write-replacement-${entry.id}-mode" ?disabled=${disabled}>
            <option value="unchanged">${rule.replacementConfigured
              ? rule.replacementHasValue ? 'Keep configured replacement' : 'Keep empty replacement'
              : 'Keep absent replacement'}</option>
            <option value="replace">Replace</option>
            <option value="clear">Set empty replacement</option>
          </select>
          <textarea id="content-rule-write-replacement-${entry.id}-value" maxlength="65536"
            aria-label="Content replacement replacement" autocomplete="off"
            placeholder="New replacement expression (write-only)" .readOnly=${disabled}></textarea>
        </div>
      </div>
      <div class="privacy-note section">
        Current content expressions stay inside the GUI core. Draft review exposes only replacement intent.
      </div>
    `;
  }

  private renderSignatureEditor(entry: DrawerEntry) {
    const signature = this.snapshot?.securityAssets?.signatures.find(item => item.id === entry.id);
    if (!signature) return nothing;
    const disabled = this.snapshot?.source === 'live' && !this.draftAvailable;
    const prefix = this.originPrefix(entry);
    const path = (field: string) => `${prefix ?? ''}${field}`;
    const scalar = <T extends ConfigScalar>(field: string, fallback: T): T =>
      this.persistentValue(path(field), fallback);
    const locked = (field: string): boolean => this.originReadOnly(path(field), disabled);
    return html`
      <div class="form-grid wide-form-grid">
        <label for="signature-category-${entry.id}">Category</label>
        <input id="signature-category-${entry.id}" maxlength="128" .value=${scalar('cat', signature.category)}
          .readOnly=${locked('cat')} />
        <label for="signature-name-${entry.id}">Name</label>
        <input id="signature-name-${entry.id}" maxlength="128" .value=${scalar('name', signature.name)}
          .readOnly=${locked('name')} />
        <label for="signature-side-${entry.id}">Connection side</label>
        <select id="signature-side-${entry.id}" .value=${scalar('side', signature.side)} ?disabled=${locked('side')}>
          <option value="client">Client</option>
          <option value="server">Server</option>
        </select>
        <label for="signature-severity-${entry.id}">Severity</label>
        <input id="signature-severity-${entry.id}" type="number" min="-2147483648" max="2147483647"
          .value=${String(scalar('severity', signature.severity))} .readOnly=${locked('severity')} />
        <label for="signature-group-${entry.id}">Group</label>
        <input id="signature-group-${entry.id}" maxlength="128" .value=${scalar('group', signature.group)}
          .readOnly=${locked('group')} />
        <label for="signature-enables-${entry.id}">Enables</label>
        <input id="signature-enables-${entry.id}" maxlength="128" .value=${scalar('enables', signature.enables)}
          .readOnly=${locked('enables')} />
        <label for="signature-engine-${entry.id}">Engine</label>
        <input id="signature-engine-${entry.id}" maxlength="128" .value=${scalar('engine', signature.engine)}
          .readOnly=${locked('engine')} />
      </div>
      <div class="section">
        <h3>Ordered flow</h3>
        <div class="reference-stack" role="group" aria-label="Signature flow steps">
          ${signature.flow.map((step, index) => html`
            <button class="reference" type="button"
              @click=${(event: MouseEvent) => this.openSignatureFlow(
                step.id, event.currentTarget as HTMLElement,
              )}>
              <span><strong>${index + 1}. ${step.side.toUpperCase()} · ${step.type}</strong>
                · bytes ${step.bytesStart}…${step.bytesMax}
                · ${step.expressionConfigured ? 'expression configured' : 'expression missing'}</span>
              <span aria-hidden="true">→</span>
            </button>
          `)}
        </div>
      </div>
      <div class="privacy-note section">
        Signature expressions stay inside the GUI core. Open a flow step to rotate one through a write-only control.
      </div>
    `;
  }

  private renderSignatureFlowEditor(entry: DrawerEntry) {
    const signature = this.snapshot?.securityAssets?.signatures
      .find(item => item.flow.some(step => step.id === entry.id));
    const step = signature?.flow.find(item => item.id === entry.id);
    if (!signature || !step) return nothing;
    const disabled = this.snapshot?.source === 'live' && !this.draftAvailable;
    const prefix = this.originPrefix(entry);
    const path = (field: string) => `${prefix ?? ''}${field}`;
    const scalar = <T extends ConfigScalar>(field: string, fallback: T): T =>
      this.persistentValue(path(field), fallback);
    const locked = (field: string): boolean => this.originReadOnly(path(field), disabled);
    return html`
      <div class="form-grid wide-form-grid">
        <label>Signature</label><span>${signature.name}</span>
        <label for="signature-flow-side-${entry.id}">Direction</label>
        <select id="signature-flow-side-${entry.id}" .value=${scalar('side', step.side)} ?disabled=${locked('side')}>
          <option value="r">Read</option>
          <option value="w">Write</option>
        </select>
        <label for="signature-flow-type-${entry.id}">Matcher</label>
        <select id="signature-flow-type-${entry.id}" .value=${scalar('type', step.type)} ?disabled=${locked('type')}>
          <option value="regex">Regular expression</option>
          <option value="simple">Simple bytes</option>
        </select>
        <label for="signature-flow-start-${entry.id}">Byte offset</label>
        <input id="signature-flow-start-${entry.id}" type="number" min="0"
          .value=${String(scalar('bytes_start', step.bytesStart))} .readOnly=${locked('bytes_start')} />
        <label for="signature-flow-maximum-${entry.id}">Byte window</label>
        <input id="signature-flow-maximum-${entry.id}" type="number" min="0"
          .value=${String(scalar('bytes_max', step.bytesMax))} .readOnly=${locked('bytes_max')} />
        <label for="signature-flow-write-expression-${entry.id}-mode">Expression</label>
        <div class="write-only-control">
          <select id="signature-flow-write-expression-${entry.id}-mode" ?disabled=${disabled}>
            <option value="unchanged">${step.expressionConfigured ? 'Keep configured expression' : 'Keep empty'}</option>
            <option value="replace">Replace</option>
          </select>
          <textarea id="signature-flow-write-expression-${entry.id}-value" maxlength="65536"
            aria-label="Signature expression replacement" autocomplete="off"
            placeholder="New expression (write-only)" .readOnly=${disabled}></textarea>
        </div>
      </div>
      <div class="privacy-note section">
        The current matcher expression is never serialized to the browser. A replacement is redacted in draft review.
      </div>
    `;
  }

  private originPrefix(entry: DrawerEntry): string | undefined {
    if (!this.snapshot) return undefined;
    if (entry.kind === 'settings') return 'settings.';
    if (entry.kind === 'captures') return 'captures.';
    if (entry.kind === 'authority') {
      const index = this.snapshot.securityAssets?.certificateAuthorities.findIndex(item => item.id === entry.id) ?? -1;
      return index < 0 ? undefined : `tls_ca.[${index}].`;
    }
    if (entry.kind === 'content-rule') {
      const profiles = this.snapshot.profiles.filter(item => item.content !== null);
      const profileIndex = profiles.findIndex(item => item.content?.rules.some(rule => rule.id === entry.id));
      const ruleIndex = profileIndex < 0 ? -1 : profiles[profileIndex]?.content?.rules
        .findIndex(rule => rule.id === entry.id) ?? -1;
      return profileIndex < 0 || ruleIndex < 0
        ? undefined : `content_profiles.[${profileIndex}].content_rules.[${ruleIndex}].`;
    }
    if (entry.kind === 'signature' || entry.kind === 'signature-flow') {
      const signature = entry.kind === 'signature'
        ? this.snapshot.securityAssets?.signatures.find(item => item.id === entry.id)
        : this.snapshot.securityAssets?.signatures.find(item => item.flow.some(step => step.id === entry.id));
      if (!signature) return undefined;
      const index = this.snapshot.securityAssets!.signatures
        .filter(item => item.kind === signature.kind).findIndex(item => item.id === signature.id);
      if (index < 0) return undefined;
      if (entry.kind === 'signature') return `${signature.kind}_signatures.[${index}].`;
      const flowIndex = signature.flow.findIndex(item => item.id === entry.id);
      return flowIndex < 0 ? undefined : `${signature.kind}_signatures.[${index}].flow.[${flowIndex}].`;
    }
    if (entry.kind === 'policy') {
      const index = this.snapshot.policies.findIndex(item => item.id === entry.id);
      return index < 0 ? undefined : `policy.[${index}].`;
    }
    if (entry.kind === 'address') {
      const index = this.snapshot.addresses.findIndex(item => item.id === entry.id);
      return index < 0 ? undefined : `address_objects.[${index}].`;
    }
    if (entry.kind === 'port') {
      const index = this.snapshot.ports.findIndex(item => item.id === entry.id);
      return index < 0 ? undefined : `port_objects.[${index}].`;
    }
    if (entry.kind === 'protocol') {
      const index = this.snapshot.protocols.findIndex(item => item.id === entry.id);
      return index < 0 ? undefined : `proto_objects.[${index}].`;
    }
    const profile = this.snapshot.profiles.find(item => item.id === entry.id);
    if (!profile) return undefined;
    const section = profile.routing ? 'routing' : profile.tls ? 'tls_profiles' :
      profile.detection ? 'detection_profiles' : profile.content ? 'content_profiles' :
      profile.ssh ? 'ssh_profiles' : profile.dns ? 'alg_dns_profiles' :
      profile.script ? 'script_profiles' : profile.authentication ? 'auth_profiles' : undefined;
    if (!section) return undefined;
    const index = this.snapshot.profiles.filter(item => item.type === profile.type).findIndex(item => item.id === entry.id);
    return index < 0 ? undefined : `${section}.[${index}].`;
  }

  private overlayCounts(): ReadonlyMap<string, number> {
    const counts = new Map<string, number>();
    for (const origin of this.snapshot?.valueOrigins ?? []) {
      const prefix = /^([A-Za-z][A-Za-z0-9_]*\.\[\d+\]\.)/u.exec(origin.path)?.[1];
      if (prefix) counts.set(prefix, (counts.get(prefix) ?? 0) + 1);
    }
    return counts;
  }

  private profileOriginPrefixes(): ReadonlyMap<string, string> {
    const prefixes = new Map<string, string>();
    const indexes = new Map<string, number>();
    for (const profile of this.snapshot?.profiles ?? []) {
      const section = profile.routing ? 'routing' : profile.tls ? 'tls_profiles' :
        profile.detection ? 'detection_profiles' : profile.content ? 'content_profiles' :
        profile.ssh ? 'ssh_profiles' : profile.dns ? 'alg_dns_profiles' :
        profile.script ? 'script_profiles' : profile.authentication ? 'auth_profiles' : undefined;
      if (!section) continue;
      const index = indexes.get(section) ?? 0;
      prefixes.set(profile.id, `${section}.[${index}].`);
      indexes.set(section, index + 1);
    }
    return prefixes;
  }

  private renderOverlayBadge(prefix: string | undefined, counts: ReadonlyMap<string, number>) {
    const count = prefix ? counts.get(prefix) ?? 0 : 0;
    if (count === 0) return nothing;
    return html`<span class="overlay-badge" title="${count} persistent ${count === 1 ? 'field is' : 'fields are'} overridden by an active augment">
      ${count} overridden
    </span>`;
  }

  private renderPendingBadge(kind: DrawerEntry['kind'], id: string) {
    if (!this.draftObjects.has(`${kind}:${id}`)) return nothing;
    return html`<span class="pending-badge" title="This row includes pending workspace draft values">Pending</span>`;
  }

  private renderAugmentOrigins(entry: DrawerEntry) {
    const prefix = this.originPrefix(entry);
    const origins = prefix ? this.snapshot?.valueOrigins.filter(item => item.path.startsWith(prefix)) ?? [] : [];
    if (origins.length === 0) return nothing;
    return html`
      <section class="section" aria-label="Effective value overlays">
        <h3>Effective value overlays</h3>
        ${origins.map(origin => {
          const field = origin.path.slice(prefix!.length);
          const pending = this.workspaceDraft?.changes.find(change => change.path === origin.path);
          return html`
            <article class="origin-card">
              <header class="origin-head">
                <code>${field}</code>
                <span class="origin-owner ${origin.editable ? '' : 'locked'}">
                  ${origin.editable ? 'Persistent value editable' : 'Owned by active layer'}
                </span>
              </header>
              <ol class="origin-chain" aria-label="${field} overlay chain">
                <li class="origin-step">
                  <span class="origin-kind">Persistent</span>
                  <strong class="origin-value">${this.formatConfigValue(origin.persistentValue)}</strong>
                </li>
                ${origin.layers.map(layer => html`
                  <li class="origin-step">
                    <span class="origin-kind">Augment${layer.priority === null ? '' : ` · Priority ${layer.priority}`}</span>
                    <strong class="origin-id">${layer.id}</strong>
                    <span class="origin-value">${this.formatConfigValue(layer.value)}</span>
                    ${layer.active ? html`<span class="origin-active">Active owner</span>` : nothing}
                  </li>
                `)}
                <li class="origin-step effective">
                  <span class="origin-kind">Effective</span>
                  <strong class="origin-value">${this.formatConfigValue(origin.effectiveValue)}</strong>
                </li>
                ${pending ? html`
                  <li class="origin-step pending">
                    <span class="origin-kind">Workspace draft</span>
                    <strong class="origin-value">${this.draftValueSummary(pending.path, pending.value)}</strong>
                    <span class="origin-active">Not active</span>
                  </li>
                ` : nothing}
              </ol>
            </article>`;
        })}
      </section>`;
  }

  private renderObjectUsage(object: AddressObject | PortObject | ProtocolObject | ProfileObject) {
    return html`
      <div class="section">
        <h3>Impact</h3>
        <div class="impact">This shared object is used by ${object.usedBy.length} configuration entries.</div>
        <ul class="usage">
          ${object.usedBy.map(reference => html`<li>${this.usageTargetAvailable(reference) ? html`
            <button class="usage-link" type="button"
              @click=${(event: MouseEvent) => this.openUsage(reference, event.currentTarget as HTMLElement)}>
              <strong>${reference.name}</strong><span><span class="usage-kind">${reference.kind}</span> →</span>
            </button>
          ` : html`
            <span class="usage-static"><strong>${reference.name}</strong><span class="usage-kind">${reference.kind}</span></span>
          `}</li>`)}
        </ul>
      </div>
    `;
  }

  private renderDrawerBody(entry: DrawerEntry) {
    if (entry.kind === 'policy') return this.renderPolicyEditor(entry);
    if (entry.kind === 'policy-create') return this.renderPolicyCreateEditor(entry);
    if (entry.kind === 'address') return this.renderAddressEditor(entry);
    if (entry.kind === 'address-create') return this.renderAddressCreateEditor(entry);
    if (entry.kind === 'port') return this.renderPortEditor(entry);
    if (entry.kind === 'port-create') return this.renderPortCreateEditor(entry);
    if (entry.kind === 'protocol') return this.renderProtocolEditor(entry);
    if (entry.kind === 'protocol-create') return this.renderProtocolCreateEditor(entry);
    if (entry.kind === 'settings') return this.renderSystemSettingsEditor();
    if (entry.kind === 'captures') return this.renderCaptureSettingsEditor();
    if (entry.kind === 'authority') return this.renderCertificateAuthorityEditor(entry);
    if (entry.kind === 'content-rule') return this.renderContentRuleEditor(entry);
    if (entry.kind === 'signature') return this.renderSignatureEditor(entry);
    if (entry.kind === 'signature-flow') return this.renderSignatureFlowEditor(entry);
    return this.renderProfileEditor(entry);
  }

  private renderDrawer(entry: DrawerEntry, index: number) {
    const saved = this.draftObjects.has(`${entry.kind}:${entry.id}`);
    const editLabel = entry.kind === 'address-create' ? 'Create address object'
      : entry.kind === 'port-create' ? 'Create port object'
        : entry.kind === 'protocol-create' ? 'Create protocol object'
          : entry.kind === 'policy-create' ? 'Create policy' : `Edit ${entry.title}`;
    const closeLabel = `Close ${entry.title}`;
    const visibleDepth = Math.min(index, 5);
    const active = index === this.drawers.length - 1;
    const draftableKinds: ReadonlyArray<DrawerEntry['kind']> = [
      'policy', 'address', 'port', 'protocol', 'settings', 'captures', 'authority',
      'signature', 'signature-flow',
      'content-rule',
    ];
    const profile = entry.kind === 'profile'
      ? this.snapshot?.profiles.find(item => item.id === entry.id)
      : undefined;
    const mappedProfile = Boolean(
      profile?.routing || profile?.tls || profile?.detection || profile?.content || profile?.ssh || profile?.dns ||
      profile?.script || profile?.authentication,
    );
    const draftable = ['address-create', 'port-create', 'protocol-create', 'policy-create'].includes(entry.kind)
      ? this.structuralDraftsAvailable
      : this.snapshot?.source !== 'live' ||
        (this.draftAvailable && (draftableKinds.includes(entry.kind) || mappedProfile));
    const readOnly = !draftable;
    const dirty = this.dirtyDrawerKeys.has(this.drawerKey(entry));
    const drawerDraftPaths = this.draftPathsForDrawer(entry);
    const removalArmed = this.draftRemovalArmedKey === this.drawerKey(entry);
    const deleteTarget = this.structuralDeleteTarget(entry);
    const deletePending = deleteTarget ? this.pendingStructuralDelete(deleteTarget) : false;
    const deleteBlocker = deleteTarget ? this.structuralDeleteBlocker(entry, deleteTarget) : undefined;
    const deleteArmed = this.structuralDeleteArmedKey === this.drawerKey(entry);
    const closePending = active && this.pendingCloseIndex !== undefined;
    const closeFromIndex = this.pendingCloseIndex ?? index;
    return html`
      <section class="drawer ${this.focusMode && active ? 'focus-mode' : ''}"
        data-depth=${visibleDepth} role="dialog" aria-modal=${active ? 'true' : 'false'}
        aria-hidden=${active ? nothing : 'true'} aria-label=${editLabel} tabindex="-1" ?inert=${!active}
        @input=${(event: Event) => this.markDrawerDirty(entry, event)}
        @change=${(event: Event) => this.markDrawerDirty(entry, event)}>
        <header class="drawer-head">
          <div class="drawer-title"><small>${entry.kind === 'address-create'
            ? 'Create address object' : entry.kind === 'port-create'
              ? 'Create port object' : entry.kind === 'protocol-create'
                ? 'Create protocol object' : entry.kind === 'policy-create'
                  ? 'Create policy' : `Edit ${entry.kind}`}</small><h2>${entry.title}</h2></div>
          ${active ? html`
            <button class="icon-button" type="button"
              aria-label=${this.focusMode ? 'Exit focus mode' : 'Enter focus mode'}
              title=${this.focusMode ? 'Exit focus mode' : 'Focus mode'}
              @click=${() => { this.focusMode = !this.focusMode; }}>⛶</button>
          ` : nothing}
          <button class="icon-button" type="button" aria-label=${closeLabel}
            @click=${() => this.requestCloseDrawer(index)}>×</button>
        </header>
        <div class="drawer-body">
          ${this.renderDrawerBody(entry)}
          ${this.renderAugmentOrigins(entry)}
        </div>
        <footer class="drawer-foot">
          ${closePending ? html`
            <span class="validation warning" role="alert">${closeFromIndex === index
              ? 'Discard unsaved changes in this editor?'
              : 'Discard unsaved changes in nested editors?'}</span>
            <button class="secondary" type="button" data-keep-editing
              @click=${() => this.keepEditing()}>Keep editing</button>
            <button class="secondary danger-button" type="button"
              @click=${() => this.discardDrawerChanges(closeFromIndex)}>Discard changes</button>
          ` : html`
            <span class="validation ${dirty ? 'warning' : ''}" role="status" aria-live="polite">
              ${this.drawerError ?? this.draftError ?? (dirty ? 'Unsaved changes' : readOnly ? 'Read-only runtime view' : saved ? 'Saved to draft' : 'Validation ready')}
            </span>
            ${drawerDraftPaths.length > 0 ? html`
              <button class="secondary danger-button" type="button"
                ?disabled=${dirty || this.draftSaving || this.draftValidating || this.draftCommitting}
                @click=${() => this.removeDrawerDraftChanges(entry)}>
                ${removalArmed
                  ? `Confirm remove ${drawerDraftPaths.length} draft change${drawerDraftPaths.length === 1 ? '' : 's'}`
                  : `Remove ${drawerDraftPaths.length} draft change${drawerDraftPaths.length === 1 ? '' : 's'}`}
              </button>
            ` : nothing}
            ${deleteTarget && (this.structuralDraftsAvailable || deletePending) ? html`
              <button class="secondary danger-button" type="button"
                title=${deleteBlocker ?? `Add ${deleteTarget.label} deletion to the workspace draft`}
                ?disabled=${deletePending || deleteBlocker !== undefined || this.draftSaving ||
                  this.draftValidating || this.draftCommitting}
                @click=${() => this.deleteStructuralEntry(entry)}>
                ${deletePending ? 'Deletion pending'
                  : deleteArmed ? `Confirm delete ${deleteTarget.label}` : `Delete ${deleteTarget.label}`}
              </button>
            ` : nothing}
            <button class="secondary" type="button" @click=${() => this.requestCloseDrawer(index)}>Cancel</button>
            <button class="primary" type="button"
              ?disabled=${readOnly || this.draftSaving || this.draftCommitting}
              @click=${() => this.saveToDraft(entry)}>${this.draftSaving ? 'Saving…' : 'Save to draft'}</button>
          `}
        </footer>
      </section>
    `;
  }

  protected render() {
    if (this.loadingError) return html`<div class="error" role="alert">${this.loadingError}</div>`;
    const controlFreshness = classifyFreshness(this.systemStatus.lastSuccessAtUnixMs, 5_000);
    const activeAlertCount = this.operationalAlerts.alerts.length;
    const hasCriticalAlert = this.operationalAlerts.alerts.some(alert => alert.severity === 'critical');
    const alertTone = this.alertsError || hasCriticalAlert ? 'danger' : activeAlertCount > 0 ? 'warning' : 'success';
    const streamTone = this.eventStreamError || this.eventStreamState === 'invalid' ? 'danger' :
      this.eventStreamState === 'live' ? 'success' : 'warning';
    const activeJobCount = this.backendJobs.jobs.filter(job =>
      job.state === 'queued' || job.state === 'running' || job.state === 'cancelling').length;
    const failedJobCount = this.backendJobs.jobs.filter(job => job.state === 'failed').length;
    const jobTone = this.jobsError ? 'danger' : !this.jobsAvailable ? 'warning' :
      activeJobCount > 0 ? 'warning' : failedJobCount > 0 ? 'danger' : 'success';
    return html`
      <div class="shell" @keydown=${this.handleKeydown}>
        <aside class="sidebar">
          <div class="brand"><span class="brand-mark">S</span><span>Smithproxy</span></div>
          <nav aria-label="Primary navigation">
            ${navigation.map((item, index) => html`
              <button type="button" aria-current=${this.activeSection === item ? 'page' : nothing} title=${item} @click=${() => { this.activeSection = item; }}>
                <span class="nav-icon" aria-hidden="true">${['⌂', '⌁', '◇', '≣', '⌁', '≡', '⚙'][index]}</span>
                <span class="nav-label">${item}</span>
              </button>
            `)}
          </nav>
        </aside>
        <main class="main">
          <header class="topbar">
            <h1>${this.activeSection}</h1>
            <p>${this.runtime?.mode === 'embedded' ? 'Saslik Tools' : 'Smithproxy management'}</p>
            ${this.snapshot?.source === 'live' && this.draftChangeCount > 0 ? html`
              <button class="secondary" type="button"
                ?disabled=${this.drawers.length > 0}
                @click=${() => {
                  this.discardDraftArmed = false;
                  this.activeSection = 'Draft';
                }}>Review draft · ${this.draftChangeCount}</button>
            ` : nothing}
            <input class="search" type="search" aria-label="Search" maxlength="128"
              placeholder="Search configuration" .value=${this.searchQuery}
              @input=${(event: InputEvent) => this.updateSearch((event.currentTarget as HTMLInputElement).value)} />
          </header>
          <div class="workspace">
            <div class="content-layer" ?inert=${this.drawers.length > 0}>${this.renderContent()}</div>
            ${this.drawers.map((entry, index) => this.renderDrawer(entry, index))}
          </div>
        </main>
        <footer class="statusbar" aria-label="System status">
          <span class="system-state ${this.systemStatus.core === 'online' ? 'success' : this.systemStatus.core === 'offline' ? 'danger' : 'warning'}">
            ● Core: ${displayState(this.systemStatus.core)}
          </span>
          <span class="system-state ${statusTone(this.systemStatus)}" title=${this.systemStatusTitle()} aria-live="polite">
            ● Smithproxy: ${displayState(this.systemStatus.smithproxy)}
          </span>
          <button class="status-action status-secondary system-state ${alertTone}" type="button"
            title=${this.alertsError ?? (activeAlertCount ? 'Open active operational alerts' : 'No active operational alerts')}
            aria-live="polite"
            @click=${() => { this.activeSection = 'Dashboard'; }}>
            ● Alerts: ${this.alertsError ? 'Unavailable' : activeAlertCount ? `${activeAlertCount} active` : 'Clear'}
          </button>
          <button class="status-action status-secondary system-state ${this.freshnessTone(controlFreshness.state)}" type="button"
            title="Last successful authenticated control-plane probe: ${this.sampleAgeLabel(this.systemStatus.lastSuccessAtUnixMs)}"
            @click=${() => { this.activeSection = 'Monitoring'; }}>
            ● Freshness: ${freshnessLabel(controlFreshness.state)}
          </button>
          <button class="status-action status-secondary system-state ${streamTone}" type="button"
            title=${this.eventStreamError ?? this.eventsError ?? 'Open operational event transport health'}
            @click=${() => { this.activeSection = 'Monitoring'; }}>
            ● Events: ${displayState(this.eventStreamState)}
          </button>
          <button class="status-action status-secondary system-state ${jobTone}" type="button"
            title=${this.jobsError ?? 'Open the bounded backend job queue'}
            @click=${() => { this.activeSection = 'System'; }}>
            ● Jobs: ${this.jobsError || !this.jobsAvailable
              ? 'Unavailable' : activeJobCount > 0 ? `${activeJobCount} active` : 'Idle'}
          </button>
          <span class="status-secondary ${this.draftChangeCount ? 'draft' : ''}">Draft: ${this.draftChangeCount} changes</span>
          <span class="status-secondary" title=${this.configError ?? this.snapshot?.detail ?? ''}>
            Config: ${this.snapshot?.source === 'live'
              ? `${displayState(this.snapshot.state)}${this.configError ? ' · refresh failed' : ''}`
              : this.snapshot
                ? this.configError ? 'Preview · live unavailable' : 'Preview'
                : this.configReadAvailable ? 'Loading' : 'Unavailable'}
            ${this.configRefreshDeferred ? ' · refresh paused' : ''}
          </span>
          <span class="status-secondary system-state ${this.gatewayStatus().tone}"
            title=${this.gatewayStatus().detail}>● Gateway: ${this.gatewayStatus().label}</span>
          <span class="status-tertiary">API: ${this.apiVersion}</span><span class="spacer"></span>
          <span class="status-tertiary">Revision ${this.snapshot?.revision ?? 'runtime'}</span>
        </footer>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'smithproxy-gui': SmithproxyApp;
  }
}
