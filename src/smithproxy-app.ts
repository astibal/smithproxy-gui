import {LitElement, css, html, nothing} from 'lit';
import {customElement, property, state} from 'lit/decorators.js';
import {ApiConfigClient} from './api/config-client';
import {FakeConfigClient} from './api/fake-client';
import type {
  AddressObject,
  ConfigSnapshot,
  PolicySummary,
  PortObject,
  ProfileObject,
  ProtocolObject,
} from './api/models';
import {
  SystemClient,
  type NeighborSnapshot,
  type RuntimeMetricsSnapshot,
  type SessionActivitySnapshot,
  type TlsCacheSnapshot,
} from './api/system-client';
import {readRuntimeConfig, type RuntimeConfig} from './config/runtime-config';
import {drawerRouteSearch, parseDrawerRoute} from './state/drawer-route';
import {DrawerStore, type DrawerEntry} from './state/drawer-store';
import {
  connectingSystemStatus,
  displayState,
  statusFromFailure,
  statusFromSnapshot,
  statusTone,
  type SystemStatus,
} from './state/system-status';

const navigation = ['Dashboard', 'Network', 'Objects', 'Policy', 'Monitoring', 'Logs', 'System'];

const initialRuntimeMetrics: RuntimeMetricsSnapshot = {
  state: 'starting',
  detail: 'Waiting for the first runtime metrics sample.',
  checkedAtUnixMs: null,
  lastSuccessAtUnixMs: null,
  totals: {workers: 0, sessionsTotal: 0, sessionsActive: 0, bytesUp: 0, bytesDown: 0},
  listeners: [],
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

@customElement('smithproxy-gui')
export class SmithproxyApp extends LitElement {
  @property({reflect: true}) mode: 'standalone' | 'embedded' = 'standalone';
  @state() private snapshot?: ConfigSnapshot;
  @state() private loadingError?: string;
  @state() private activeSection = 'Dashboard';
  @state() private drawers: ReadonlyArray<DrawerEntry> = [];
  @state() private draftObjects = new Set<string>();
  @state() private systemStatus: SystemStatus = connectingSystemStatus;
  @state() private apiVersion = 'discovering';
  @state() private runtimeMetrics: RuntimeMetricsSnapshot = initialRuntimeMetrics;
  @state() private sessionActivity: SessionActivitySnapshot = initialSessionActivity;
  @state() private tlsCache: TlsCacheSnapshot = initialTlsCache;
  @state() private neighbors: NeighborSnapshot = initialNeighbors;
  @state() private focusMode = false;
  @state() private configWriteAvailable = false;
  @state() private configError: string | undefined;

  private readonly previewClient = new FakeConfigClient();
  private readonly drawerStore = new DrawerStore();
  private runtime?: RuntimeConfig;
  private systemClient?: SystemClient;
  private systemProbeTimer: number | undefined;
  private systemProbeInFlight = false;
  private systemProbePending = false;
  private drawerHistoryDepth = 0;
  private drawerOrigins: HTMLElement[] = [];
  private pendingReturnFocus: HTMLElement | undefined;

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
    .section-head { display: flex; align-items: end; justify-content: space-between; margin-bottom: 16px; }
    .section-head h2 { margin: 0 0 3px; font-size: 20px; }
    .section-head p { margin: 0; color: var(--app-muted); }
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
    .metrics-message { padding: 11px 13px; border: 1px solid var(--app-border); border-radius: 3px; color: var(--app-muted); }
    .privacy-note { padding: 10px 13px; border-left: 3px solid var(--app-success); background: var(--app-success-bg); color: var(--app-muted); }
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

    .table { overflow: hidden; border: 1px solid var(--app-border); border-radius: 4px; background: var(--app-surface); }
    .row { display: grid; grid-template-columns: minmax(130px, 1.2fr) minmax(130px, 1fr) minmax(110px, 1fr) 90px 80px; gap: 16px; align-items: center; width: 100%; padding: 12px 14px; border: 0; border-bottom: 1px solid var(--app-border); background: transparent; text-align: left; cursor: pointer; }
    .row:last-child { border-bottom: 0; }
    .row:not(.heading):hover { background: var(--app-raised); }
    .row.heading { color: var(--app-muted); font-size: 12px; cursor: default; }
    .row strong { font-weight: 650; }
    .status { display: inline-flex; width: fit-content; gap: 6px; align-items: center; color: var(--app-success); }
    .status::before { width: 7px; height: 7px; border-radius: 50%; background: currentColor; content: ''; }
    .status.disabled { color: var(--app-muted); }
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
    .secondary { padding: 8px 13px; border: 1px solid var(--app-border-strong); border-radius: 3px; background: transparent; cursor: pointer; }
    .form-grid { display: grid; grid-template-columns: minmax(120px, 0.35fr) minmax(240px, 1fr); gap: 18px 24px; max-width: 920px; }
    .form-grid label { align-self: center; color: var(--app-muted); }
    .form-grid input, .form-grid select, .form-grid textarea { width: 100%; padding: 9px 10px; border: 1px solid var(--app-border); border-radius: 3px; background: var(--app-input); color: var(--app-text); }
    .form-grid input[readonly], .form-grid select:disabled { border-style: dashed; opacity: .8; }
    .reference-stack { display: grid; gap: 7px; }
    .reference { display: flex; align-items: center; justify-content: space-between; width: 100%; padding: 10px 12px; border: 1px solid var(--app-border); border-radius: 3px; background: var(--app-input); cursor: pointer; }
    .section { margin-top: 28px; padding-top: 20px; border-top: 1px solid var(--app-border); }
    .section h3 { margin: 0 0 12px; font-size: 15px; }
    .impact { padding: 12px 14px; border: 1px solid color-mix(in srgb, var(--app-warning) 48%, var(--app-border)); border-radius: 3px; background: var(--app-warning-bg); color: var(--app-warning); }
    .usage { margin: 12px 0 0; padding: 0; list-style: none; }
    .usage li { padding: 7px 0; border-bottom: 1px solid var(--app-border); }

    .statusbar { grid-column: 1 / -1; display: flex; gap: 20px; align-items: center; padding: 0 12px; border-top: 1px solid var(--app-border); background: var(--app-raised); color: var(--app-muted); font-size: 12px; }
    .system-state { color: var(--app-muted); }
    .system-state.success { color: var(--app-success); }
    .system-state.warning { color: var(--app-warning); }
    .system-state.danger { color: var(--app-danger); }
    .draft { color: var(--app-warning); }
    .spacer { flex: 1; }

    .error { margin: 24px; padding: 16px; border: 1px solid var(--app-danger); border-radius: 3px; color: var(--app-danger); }
    .empty-state { display: grid; height: 100%; place-content: center; padding: 24px; color: var(--app-muted); text-align: center; }
    .empty-state h2 { margin: 0 0 6px; color: var(--app-text); }
    .empty-state p { max-width: 460px; margin: 0; }

    @keyframes slide-in { from { translate: 32px 0; opacity: 0; } }

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
      .system-grid { grid-template-columns: 1fr; }
    }

    @media (max-width: 620px) {
      .shell { grid-template: 52px minmax(0, 1fr) 30px / minmax(0, 1fr); }
      .sidebar { grid-row: 1; display: flex; align-items: center; overflow-x: auto; padding: 6px 8px; border-right: 0; border-bottom: 1px solid var(--app-border); }
      .brand { margin: 0 10px 0 0; }
      nav { display: flex; }
      nav button { width: 42px; padding: 8px; }
      .main { grid-row: 2; }
      .topbar { padding: 0 12px; }
      .topbar p, .search { display: none; }
      .content { padding: 14px; }
      .drawer { inset: 0; }
      .form-grid { grid-template-columns: 1fr; gap: 7px; }
      .form-grid label:not(:first-child) { margin-top: 10px; }
      .statusbar { grid-row: 3; }
      .statusbar span:nth-of-type(n + 3) { display: none; }
      .metric-grid { grid-template-columns: 1fr; }
      .object-row { grid-template-columns: minmax(120px, 1fr) 90px; }
      .object-row > :nth-child(3), .object-row > :nth-child(4) { display: none; }
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
      void this.probeSystem();
    } catch (error) {
      this.systemStatus = statusFromFailure(error);
    }
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
    window.addEventListener('online', this.handleOnline);
    window.addEventListener('popstate', this.handlePopState);
    void this.loadConfiguration();
  }

  disconnectedCallback(): void {
    this.clearSystemProbe();
    document.removeEventListener('visibilitychange', this.handleVisibilityChange);
    window.removeEventListener('online', this.handleOnline);
    window.removeEventListener('popstate', this.handlePopState);
    super.disconnectedCallback();
  }

  private readonly handleVisibilityChange = (): void => {
    if (document.visibilityState === 'hidden') {
      this.clearSystemProbe();
    } else {
      void this.probeSystem();
    }
  };

  private readonly handleOnline = (): void => {
    void this.probeSystem();
  };

  private readonly handlePopState = (): void => {
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
    try {
      this.systemStatus = statusFromSnapshot(await this.systemClient.status());
      try {
        this.runtimeMetrics = await this.systemClient.metricsSummary();
      } catch (error) {
        this.runtimeMetrics = {
          ...this.runtimeMetrics,
          state: 'unavailable',
          detail: error instanceof Error ? error.message : 'Runtime metrics are unavailable.',
        };
      }
      try {
        this.sessionActivity = await this.systemClient.sessionActivity();
      } catch (error) {
        this.sessionActivity = {
          ...this.sessionActivity,
          state: 'unavailable',
          detail: error instanceof Error ? error.message : 'Session activity is unavailable.',
        };
      }
      try {
        this.tlsCache = await this.systemClient.tlsCacheSummary();
      } catch (error) {
        this.tlsCache = {
          ...this.tlsCache,
          state: 'unavailable',
          detail: error instanceof Error ? error.message : 'TLS cache metrics are unavailable.',
        };
      }
      try {
        this.neighbors = await this.systemClient.neighborSummary();
      } catch (error) {
        this.neighbors = {
          ...this.neighbors,
          state: 'unavailable',
          detail: error instanceof Error ? error.message : 'Neighborhood metrics are unavailable.',
        };
      }
      if (this.apiVersion === 'unavailable') void this.loadCapabilities();
    } catch (error) {
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

  private async loadCapabilities(): Promise<void> {
    if (!this.systemClient) return;
    try {
      const capabilities = await this.systemClient.capabilities();
      this.apiVersion = capabilities.apiVersion;
      this.configWriteAvailable = capabilities.features.configWrite;
      if (capabilities.features.configRead && this.runtime && this.snapshot?.source !== 'live') {
        try {
          this.snapshot = await new ApiConfigClient(this.runtime.apiBase).loadSnapshot();
          this.configError = undefined;
          this.restoreDrawerRoute();
        } catch (error) {
          this.configError = error instanceof Error ? error.message : 'Live configuration is unavailable.';
        }
      }
    } catch {
      this.apiVersion = 'unavailable';
    }
  }

  private systemStatusTitle(): string {
    const checked = this.systemStatus.checkedAtUnixMs === null
      ? 'not checked yet'
      : new Date(this.systemStatus.checkedAtUnixMs).toLocaleString();
    return `${this.systemStatus.detail} Last Smithproxy check: ${checked}.`;
  }

  private async loadConfiguration(): Promise<void> {
    try {
      this.snapshot = await this.previewClient.loadSnapshot();
      this.restoreDrawerRoute();
      await this.loadCapabilities();
    } catch (error) {
      this.loadingError = error instanceof Error ? error.message : 'Unable to load configuration.';
    }
  }

  private openPolicy(policy: PolicySummary, origin?: HTMLElement): void {
    this.drawerStore.open({kind: 'policy', id: policy.id, title: policy.name});
    this.drawerOrigins = [
      ...this.drawerOrigins.slice(0, this.drawerStore.entries.length - 1),
      ...(origin ? [origin] : []),
    ];
    this.focusMode = false;
    this.syncDrawers(true);
  }

  private openAddress(id: string, origin?: HTMLElement): void {
    const address = this.snapshot?.addresses.find(item => item.id === id);
    if (!address) return;
    this.drawerStore.open({kind: 'address', id: address.id, title: address.name});
    this.drawerOrigins = [
      ...this.drawerOrigins.slice(0, this.drawerStore.entries.length - 1),
      ...(origin ? [origin] : []),
    ];
    this.focusMode = false;
    this.syncDrawers(true);
  }

  private openPort(id: string, origin?: HTMLElement): void {
    const port = this.snapshot?.ports.find(item => item.id === id);
    if (!port) return;
    this.openObjectDrawer({kind: 'port', id: port.id, title: port.name}, origin);
  }

  private openProtocol(id: string, origin?: HTMLElement): void {
    const protocol = this.snapshot?.protocols.find(item => item.id === id);
    if (!protocol) return;
    this.openObjectDrawer({kind: 'protocol', id: protocol.id, title: protocol.name}, origin);
  }

  private openProfile(id: string, origin?: HTMLElement): void {
    const profile = this.snapshot?.profiles.find(item => item.id === id);
    if (!profile) return;
    this.openObjectDrawer({kind: 'profile', id: profile.id, title: profile.name}, origin);
  }

  private openObjectDrawer(entry: DrawerEntry, origin?: HTMLElement): void {
    this.drawerStore.open(entry);
    this.drawerOrigins = [
      ...this.drawerOrigins.slice(0, this.drawerStore.entries.length - 1),
      ...(origin ? [origin] : []),
    ];
    this.focusMode = false;
    this.syncDrawers(true);
  }

  private closeDrawer(index: number): void {
    const levels = this.drawerStore.entries.length - index;
    const returnFocus = this.drawerOrigins[index];
    this.drawerStore.closeFrom(index);
    this.drawerOrigins = this.drawerOrigins.slice(0, index);
    this.focusMode = false;
    this.syncDrawers(false);
    if (levels > 0 && this.drawerHistoryDepth >= levels) {
      this.drawerHistoryDepth -= levels;
      this.pendingReturnFocus = returnFocus;
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
    this.drawerStore.clear();
    this.drawerOrigins = [];
    let valid = true;
    for (const entry of route) {
      const candidate = this.drawerCandidate(entry);
      if (!candidate) { valid = false; break; }
      this.drawerStore.open({kind: entry.kind, id: candidate.id, title: candidate.name});
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
    if (this.drawers[0] && this.drawers[0].kind !== 'policy') this.activeSection = 'Objects';
    this.focusMode = false;
    void this.updateComplete.then(() => this.focusActiveDrawer());
  }

  private drawerCandidate(entry: Pick<DrawerEntry, 'kind' | 'id'>) {
    if (!this.snapshot) return undefined;
    if (entry.kind === 'policy') return this.snapshot.policies.find(item => item.id === entry.id);
    if (entry.kind === 'address') return this.snapshot.addresses.find(item => item.id === entry.id);
    if (entry.kind === 'port') return this.snapshot.ports.find(item => item.id === entry.id);
    if (entry.kind === 'protocol') return this.snapshot.protocols.find(item => item.id === entry.id);
    return this.snapshot.profiles.find(item => item.id === entry.id);
  }

  private focusActiveDrawer(): void {
    if (this.drawers.length === 0) return;
    const drawers = this.renderRoot.querySelectorAll<HTMLElement>('.drawer');
    const active = drawers.item(drawers.length - 1);
    const target = active?.querySelector<HTMLElement>(
      '.drawer-body input:not([disabled]), .drawer-body select:not([disabled]), ' +
      '.drawer-body textarea:not([disabled]), .drawer-body button:not([disabled])',
    );
    (target ?? active)?.focus();
  }

  private saveToDraft(entry: DrawerEntry): void {
    this.draftObjects = new Set(this.draftObjects).add(`${entry.kind}:${entry.id}`);
  }

  private handleKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape' && this.drawers.length > 0) {
      event.preventDefault();
      this.closeDrawer(this.drawers.length - 1);
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

  private renderPolicyList() {
    return html`
      <div class="content">
        <div class="section-head">
          <div><h2>Policies</h2><p>Traffic decisions and inspection behavior</p></div>
          <button class="primary" type="button"
            ?disabled=${this.snapshot?.source === 'live' && !this.configWriteAvailable}>New policy</button>
        </div>
        <div class="table" role="group" aria-label="Policies">
          <div class="row heading" aria-hidden="true">
            <span>Name</span><span>Source</span><span>Destination</span><span>Action</span><span>Status</span>
          </div>
          ${this.snapshot?.policies.map(policy => html`
            <button class="row" type="button"
              @click=${(event: MouseEvent) => this.openPolicy(policy, event.currentTarget as HTMLElement)}>
              <strong>${policy.name}</strong>
              <span>${this.referenceSummary(policy.sources)}</span>
              <span>${this.referenceSummary(policy.destinations)}</span>
              <span class="action">${policy.action}</span>
              <span class="status ${policy.enabled ? '' : 'disabled'}">${policy.enabled ? 'Enabled' : 'Disabled'}</span>
            </button>
          `)}
        </div>
      </div>
    `;
  }

  private referenceSummary(references: PolicySummary['sources']): string {
    if (references.length === 0) return 'None';
    const [first, ...rest] = references;
    return `${first!.name}${rest.length > 0 ? ` +${rest.length}` : ''}`;
  }

  private renderObjects() {
    return html`
      <div class="content">
        <div class="section-head">
          <div><h2>Configuration objects</h2><p>Reusable values referenced by policy</p></div>
          <button class="primary" type="button"
            ?disabled=${this.snapshot?.source === 'live' && !this.configWriteAvailable}>New address object</button>
        </div>
        <section class="object-section">
          <h3>Address objects</h3>
          <div class="table" role="group" aria-label="Address objects">
            <div class="row object-row heading" aria-hidden="true">
              <span>Name</span><span>Type</span><span>Value</span><span>Uses</span>
            </div>
            ${this.snapshot?.addresses.map(address => html`
              <button class="row object-row" type="button"
                @click=${(event: MouseEvent) => this.openAddress(address.id, event.currentTarget as HTMLElement)}>
                <strong>${address.name}</strong>
                <span class="action">${address.type}</span>
                <span class="object-value">${address.value}</span>
                <span>${address.usedBy.length}</span>
              </button>
            `)}
          </div>
        </section>
        <section class="object-section">
          <h3>Port objects</h3>
          <div class="table" role="group" aria-label="Port objects">
            <div class="row object-row heading" aria-hidden="true">
              <span>Name</span><span>Type</span><span>Value</span><span>Uses</span>
            </div>
            ${this.snapshot?.ports.map(port => html`
              <button class="row object-row" type="button"
                @click=${(event: MouseEvent) => this.openPort(port.id, event.currentTarget as HTMLElement)}>
                <strong>${port.name}</strong><span>Port range</span>
                <span class="object-value">${port.start === port.end ? port.start : `${port.start}–${port.end}`}</span>
                <span>${port.usedBy.length}</span>
              </button>
            `)}
          </div>
        </section>
        <section class="object-section">
          <h3>Protocol objects</h3>
          <div class="table" role="group" aria-label="Protocol objects">
            <div class="row object-row heading" aria-hidden="true">
              <span>Name</span><span>Type</span><span>Value</span><span>Uses</span>
            </div>
            ${this.snapshot?.protocols.map(protocol => html`
              <button class="row object-row" type="button"
                @click=${(event: MouseEvent) => this.openProtocol(protocol.id, event.currentTarget as HTMLElement)}>
                <strong>${protocol.name}</strong><span>IP protocol</span>
                <span class="object-value">${protocol.number}</span><span>${protocol.usedBy.length}</span>
              </button>
            `)}
          </div>
        </section>
        <section class="object-section">
          <h3>Profiles and routing</h3>
          <div class="table" role="group" aria-label="Profiles and routing">
            <div class="row object-row heading" aria-hidden="true">
              <span>Name</span><span>Type</span><span>Value exposure</span><span>Uses</span>
            </div>
            ${this.snapshot?.profiles.map(profile => html`
              <button class="row object-row" type="button"
                @click=${(event: MouseEvent) => this.openProfile(profile.id, event.currentTarget as HTMLElement)}>
                <strong>${profile.name}</strong><span class="action">${profile.type}</span>
                <span>${profile.routing || profile.tls || profile.detection || profile.content || profile.ssh || profile.dns
                  ? 'Typed details' : 'Metadata only'}</span><span>${profile.usedBy.length}</span>
              </button>
            `)}
          </div>
        </section>
      </div>
    `;
  }

  private renderNetwork() {
    const metrics = this.runtimeMetrics;
    return html`
      <div class="content dashboard">
        <div class="section-head">
          <div><h2>Listener workload</h2><p>Runtime view of Smithproxy network entry points</p></div>
        </div>
        ${this.renderNeighborSummary()}
        ${metrics.state === 'ready' ? nothing : html`
          <div class="metrics-message" role="status">${metrics.detail}</div>
        `}
        <div class="card-grid" aria-label="Network listeners">
          ${metrics.listeners.map(listener => html`
            <article class="domain-card">
              <header>
                <div><h3>${listener.name}</h3><p>${listener.workers} worker${listener.workers === 1 ? '' : 's'}</p></div>
                <span class="status ${listener.workers > 0 ? '' : 'disabled'}">${listener.workers > 0 ? 'Running' : 'Idle'}</span>
              </header>
              <dl>
                <dt>Active sessions</dt><dd>${listener.sessionsActive.toLocaleString()}</dd>
                <dt>Total sessions</dt><dd>${listener.sessionsTotal.toLocaleString()}</dd>
                <dt>Traffic up</dt><dd>${this.formatBytes(listener.bytesUp)}</dd>
                <dt>Traffic down</dt><dd>${this.formatBytes(listener.bytesDown)}</dd>
              </dl>
            </article>
          `)}
          ${metrics.listeners.length === 0 ? html`<div class="metrics-message">No listener samples are available yet.</div>` : nothing}
        </div>
      </div>
    `;
  }

  private renderNeighborSummary() {
    const neighbors = this.neighbors;
    return html`
      <section class="runtime-summary" aria-label="Neighborhood activity">
        <div class="runtime-heading">
          <div><h3>Neighborhood activity</h3><p>Privacy-safe aggregates for recently observed endpoints</p></div>
          <span class="runtime-state ${neighbors.state === 'ready' ? 'success' : neighbors.state === 'unavailable' ? 'danger' : 'warning'}"
            title=${neighbors.detail}>● ${displayState(neighbors.state)}</span>
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
        <div class="privacy-note">Hostnames, tags, labels, and per-endpoint timelines remain inside the GUI core.</div>
      </section>
    `;
  }

  private availabilityLabel(): string {
    if (this.systemStatus.availabilitySamples === 0) return 'No samples';
    const ratio = this.systemStatus.availabilitySuccessful / this.systemStatus.availabilitySamples;
    return `${(ratio * 100).toFixed(ratio === 1 ? 0 : 1)}%`;
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

  private runtimeTone(): 'success' | 'warning' | 'danger' {
    if (this.runtimeMetrics.state === 'ready') return 'success';
    if (this.runtimeMetrics.state === 'unavailable') return 'danger';
    return 'warning';
  }

  private renderRuntimeSummary() {
    const metrics = this.runtimeMetrics;
    return html`
      <section class="runtime-summary" aria-label="Runtime metrics summary">
        <div class="runtime-heading">
          <div><h3>Runtime traffic</h3><p>Aggregated counters reported by Smithproxy listeners</p></div>
          <span class="runtime-state ${this.runtimeTone()}" title=${metrics.detail}>
            ● ${displayState(metrics.state)}
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
      </section>
    `;
  }

  private renderTlsCache() {
    const cache = this.tlsCache;
    const utilization = cache.capacity === 0 ? 0 : Math.min(100, cache.size / cache.capacity * 100);
    return html`
      <section class="runtime-summary" aria-label="TLS interception cache">
        <div class="runtime-heading">
          <div><h3>TLS interception cache</h3><p>Aggregate certificate cache health without domain disclosure</p></div>
          <span class="runtime-state ${cache.state === 'ready' ? 'success' : cache.state === 'unavailable' ? 'danger' : 'warning'}"
            title=${cache.detail}>● ${displayState(cache.state)}</span>
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
      </section>
    `;
  }

  private renderDashboard() {
    const history = this.systemStatus.history;
    const emptySlots = Math.max(0, 60 - history.length);
    return html`
      <div class="content dashboard">
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
        ${this.renderRuntimeSummary()}
        ${this.renderTlsCache()}
        <section class="monitor-panel" aria-label="Probe history">
          <h3>Recent probe history</h3>
          <p>Up to five minutes at the current five-second sampling interval. Last success: ${this.timeLabel(this.systemStatus.lastSuccessAtUnixMs)}.</p>
          <div class="probe-history" aria-label="${history.length} probe samples">
            ${Array.from({length: emptySlots}, () => html`<span class="probe" aria-hidden="true"></span>`)}
            ${history.map(sample => html`
              <span class="probe ${sample.state}" title="${displayState(sample.state)} · ${sample.latencyMs ?? '—'} ms · ${this.timeLabel(sample.checkedAtUnixMs)}" aria-hidden="true"></span>
            `)}
          </div>
        </section>
        <div class="scope-note">
          Control-plane health and listener counters are live. TLS inspection outcomes and deeper dataplane health will be added as dedicated monitoring surfaces.
        </div>
      </div>
    `;
  }

  private renderMonitoring() {
    const metrics = this.runtimeMetrics;
    return html`
      <div class="content dashboard">
        <div class="section-head">
          <div><h2>Listener monitoring</h2><p>Live aggregate counters from the Smithproxy runtime</p></div>
        </div>
        ${this.renderRuntimeSummary()}
        ${this.renderTlsCache()}
        ${this.renderSessionActivity()}
        ${metrics.state === 'ready' ? nothing : html`
          <div class="metrics-message" role="status">${metrics.detail} Last successful sample: ${this.timeLabel(metrics.lastSuccessAtUnixMs)}.</div>
        `}
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
    return html`
      <section class="runtime-summary" aria-label="Session activity">
        <div class="runtime-heading">
          <div><h3>Live session activity</h3><p>Privacy-preserving transport aggregates</p></div>
          <span class="runtime-state ${activity.state === 'ready' ? 'success' : activity.state === 'unavailable' ? 'danger' : 'warning'}" title=${activity.detail}>
            ● ${displayState(activity.state)}
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
        ${activity.state === 'ready' ? nothing : html`<div class="metrics-message" role="status">${activity.detail}</div>`}
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
    return html`
      <div class="content dashboard">
        <div class="section-head">
          <div><h2>System integration</h2><p>Non-sensitive diagnostics for this GUI instance</p></div>
        </div>
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
        </div>
      </div>
    `;
  }

  private renderContent() {
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

  private renderPolicyEditor(entry: DrawerEntry) {
    const policy = this.snapshot?.policies.find(item => item.id === entry.id);
    if (!policy) return nothing;
    const readOnly = this.snapshot?.source === 'live' && !this.configWriteAvailable;
    const protocol = this.snapshot?.protocols.find(item => item.name === policy.protocol);
    return html`
      <div class="form-grid">
        <label for="policy-name-${entry.id}">Name</label>
        <input id="policy-name-${entry.id}" .value=${policy.name} .readOnly=${readOnly} />
        <label>Enabled</label>
        <label><input type="checkbox" .checked=${policy.enabled} ?disabled=${readOnly} /> Accept traffic for evaluation</label>
        <label>Sources</label>
        <div class="reference-stack">${policy.sources.map(reference => reference.id ? html`
          <button class="reference" type="button"
            @click=${(event: MouseEvent) => this.openAddress(reference.id!, event.currentTarget as HTMLElement)}>
            <span>${reference.name}</span><span aria-hidden="true">→</span>
          </button>
        ` : html`<span>${reference.name}</span>`)}</div>
        <label for="destination-${entry.id}">Destinations</label>
        <input id="destination-${entry.id}"
          .value=${policy.destinations.map(item => item.name).join(', ')} .readOnly=${readOnly} />
        <label for="action-${entry.id}">Action</label>
        <input id="action-${entry.id}" .value=${policy.action} .readOnly=${readOnly} />
      </div>
      <div class="section">
        <h3>Advanced</h3>
        <div class="form-grid">
          <label>Protocol</label>
          ${protocol ? html`<button class="reference" type="button"
            @click=${(event: MouseEvent) => this.openProtocol(protocol.id, event.currentTarget as HTMLElement)}>
            <span>${protocol.name}</span><span aria-hidden="true">→</span>
          </button>` : html`<span>${policy.protocol}</span>`}
          <label>Source ports</label>
          ${this.renderPortReferences(policy.sourcePorts)}
          <label>Destination ports</label>
          ${this.renderPortReferences(policy.destinationPorts)}
          <label>TLS profile</label>
          ${this.renderProfileReference('tls', policy.tlsProfile)}
          <label>Routing profile</label>
          ${this.renderProfileReference('routing', policy.routing)}
          <label>Detection profile</label>
          ${this.renderProfileReference('detection', policy.detectionProfile)}
          <label>Content profile</label>
          ${this.renderProfileReference('content', policy.contentProfile)}
          <label>SSH profile</label>
          ${this.renderProfileReference('ssh', policy.sshProfile)}
          <label>Authentication profile</label>
          ${this.renderProfileReference('authentication', policy.authProfile)}
          <label>DNS ALG profile</label>
          ${this.renderProfileReference('dns', policy.dnsProfile)}
          <label>Script profile</label>
          ${this.renderProfileReference('script', policy.scriptProfile)}
          <label>Features</label>
          <span>${policy.features.length > 0 ? policy.features.join(', ') : 'None'}</span>
        </div>
      </div>
    `;
  }

  private renderPortReferences(names: ReadonlyArray<string>) {
    return html`<div class="reference-stack">${names.map(name => {
      const port = this.snapshot?.ports.find(item => item.name === name);
      return port ? html`<button class="reference" type="button"
        @click=${(event: MouseEvent) => this.openPort(port.id, event.currentTarget as HTMLElement)}>
        <span>${port.name}</span><span aria-hidden="true">→</span>
      </button>` : html`<span>${name}</span>`;
    })}</div>`;
  }

  private renderProfileReference(type: string, name: string) {
    if (name.length === 0 || name === 'none') return html`<span>None</span>`;
    const profile = this.snapshot?.profiles.find(item => item.type === type && item.name === name);
    return profile ? html`<button class="reference" type="button"
      @click=${(event: MouseEvent) => this.openProfile(profile.id, event.currentTarget as HTMLElement)}>
      <span>${profile.name}</span><span aria-hidden="true">→</span>
    </button>` : html`<span>${name}</span>`;
  }

  private renderAddressEditor(entry: DrawerEntry) {
    const address = this.snapshot?.addresses.find(item => item.id === entry.id);
    if (!address) return nothing;
    const readOnly = this.snapshot?.source === 'live' && !this.configWriteAvailable;
    return html`
      <div class="form-grid">
        <label for="address-name-${entry.id}">Name</label>
        <input id="address-name-${entry.id}" .value=${address.name} .readOnly=${readOnly} />
        <label for="address-type-${entry.id}">Type</label>
        <select id="address-type-${entry.id}" .value=${address.type} ?disabled=${readOnly}>
          <option value="cidr">CIDR</option><option value="fqdn">FQDN</option><option value="host">Host</option><option value="subnet">Subnet</option><option value="range">Range</option>
        </select>
        <label for="address-value-${entry.id}">Address</label>
        <input id="address-value-${entry.id}" .value=${address.value} .readOnly=${readOnly} />
      </div>
      ${this.renderImpact(address)}
    `;
  }

  private renderImpact(address: AddressObject) {
    return html`
      <div class="section">
        <h3>Impact</h3>
        <div class="impact">This shared object is used by ${address.usedBy.length} configuration entries.</div>
        <ul class="usage">
          ${address.usedBy.map(reference => html`<li><strong>${reference.name}</strong> · ${reference.kind}</li>`)}
        </ul>
      </div>
    `;
  }

  private renderPortEditor(entry: DrawerEntry) {
    const port = this.snapshot?.ports.find(item => item.id === entry.id);
    if (!port) return nothing;
    const readOnly = this.snapshot?.source === 'live' && !this.configWriteAvailable;
    return html`
      <div class="form-grid">
        <label for="port-name-${entry.id}">Name</label>
        <input id="port-name-${entry.id}" .value=${port.name} .readOnly=${readOnly} />
        <label for="port-start-${entry.id}">Start</label>
        <input id="port-start-${entry.id}" type="number" min="0" max="65535"
          .value=${String(port.start)} .readOnly=${readOnly} />
        <label for="port-end-${entry.id}">End</label>
        <input id="port-end-${entry.id}" type="number" min="0" max="65535"
          .value=${String(port.end)} .readOnly=${readOnly} />
      </div>
      ${this.renderObjectUsage(port)}
    `;
  }

  private renderProtocolEditor(entry: DrawerEntry) {
    const protocol = this.snapshot?.protocols.find(item => item.id === entry.id);
    if (!protocol) return nothing;
    const readOnly = this.snapshot?.source === 'live' && !this.configWriteAvailable;
    return html`
      <div class="form-grid">
        <label for="protocol-name-${entry.id}">Name</label>
        <input id="protocol-name-${entry.id}" .value=${protocol.name} .readOnly=${readOnly} />
        <label for="protocol-number-${entry.id}">IP protocol number</label>
        <input id="protocol-number-${entry.id}" type="number" min="0" max="255"
          .value=${String(protocol.number)} .readOnly=${readOnly} />
      </div>
      ${this.renderObjectUsage(protocol)}
    `;
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
    return html`
      <div class="form-grid">
        <label>Name</label><span>${profile.name}</span>
        <label>Profile type</label><span class="action">${profile.type}</span>
        ${routing ? html`
          <label>Destination addresses</label>
          <div class="reference-stack">${routing.destinationAddresses.length === 0 ? html`<span>None</span>` :
            routing.destinationAddresses.map(name => {
              const address = this.snapshot?.addresses.find(item => item.name === name);
              return address ? html`<button class="reference" type="button"
                @click=${(event: MouseEvent) => this.openAddress(address.id, event.currentTarget as HTMLElement)}>
                <span>${name}</span><span aria-hidden="true">→</span>
              </button>` : html`<span>${name}</span>`;
            })}</div>
          <label>Destination ports</label>
          ${this.renderPortReferences(routing.destinationPorts)}
          <label>Load balancing</label><span>${routing.loadBalancingMethod}</span>
          <label>SNI rewrite</label>
          <span>${routing.rewriteSni.length === 0 ? 'Disabled' : `${routing.rewriteSni} → ${routing.rewriteSniTo}`}</span>
        ` : tls ? html`
          <label>Inspection</label><span>${tls.inspect ? 'Enabled' : 'Disabled'}</span>
          <label>Certificate validation</label>
          <span>${tls.allowInvalidCertificates || tls.allowUntrustedIssuers || tls.allowSelfSigned
            ? 'Relaxed' : 'Strict'}</span>
          <label>Certificate transparency</label><span>${tls.certificateTransparency ? 'Enabled' : 'Disabled'}</span>
          <label>OCSP stapling</label><span>${tls.ocspStapling ? 'Enabled' : 'Disabled'}</span>
          <label>Fallback bypass</label><span>${tls.noFallbackBypass ? 'Blocked' : 'Allowed'}</span>
          <label>Custom certificates only</label><span>${tls.onlyCustomCertificates ? 'Yes' : 'No'}</span>
          <label>ALPN negotiation</label><span>${tls.blockAlpn ? 'Blocked' : 'Allowed'}</span>
          <label>Client certificate action</label><span>${tls.clientCertificateAction}</span>
          <label>Client hello timeout</label><span>${tls.clientHelloTimeoutMs} ms</span>
          <label>Handshake timeout</label><span>${tls.handshakeTimeoutMs} ms</span>
          <label>SNI bypass list</label><span>${tls.sniBypassEntries} redacted entries</span>
          <label>SSL key logging</label><span>${tls.sslKeyLog ? 'Enabled' : 'Disabled'}</span>
          <label>Alerts</label><span>${tls.alerts}</span>
        ` : detection ? html`
          <label>Detection phase</label>
          <span>${['Disabled', 'Pre-read', 'Post-read'][detection.mode]}</span>
          <label>L7 engines</label><span>${detection.enginesEnabled ? 'Enabled' : 'Disabled'}</span>
          <label>Knowledge base</label><span>${detection.knowledgeBaseEnabled ? 'Enabled' : 'Disabled'}</span>
        ` : content ? html`
          <label>Payload capture</label><span>${content.writePayload ? 'Enabled' : 'Disabled'}</span>
          <label>Capture format</label><span>${content.writeFormat}</span>
          <label>Webhook</label><span>${content.webhookEnabled ? 'Enabled' : 'Disabled'}</span>
          <label>Webhook traffic lock</label><span>${content.webhookLocksTraffic ? 'Enabled' : 'Disabled'}</span>
          <label>JA4 TLS ClientHello</label><span>${content.ja4TlsClientHello ? 'Enabled' : 'Disabled'}</span>
          <label>JA4 ignores SNI</label><span>${content.ja4TlsClientHelloIgnoresSni ? 'Yes' : 'No'}</span>
          <label>JA4 TLS ServerHello</label><span>${content.ja4TlsServerHello ? 'Enabled' : 'Disabled'}</span>
          <label>JA4 HTTP</label><span>${content.ja4Http ? 'Enabled' : 'Disabled'}</span>
          <label>Session filter</label><span>${content.sessionFilterConfigured ? 'Configured · redacted' : 'Not configured'}</span>
          <label>Content rules</label><span>${content.ruleCount} redacted rules</span>
        ` : ssh ? html`
          <label>Host key</label><span>${ssh.hostKeyConfigured ? 'Configured · path redacted' : 'Missing'}</span>
          <label>Upstream host-key policy</label><span>${ssh.hostKeyPolicy}</span>
          <label>Shell</label><span>${ssh.shell ? 'Pass' : 'Reject'}</span>
          <label>Exec</label><span>${ssh.exec ? 'Pass' : 'Reject'}</span>
          <label>Subsystem</label><span>${ssh.subsystem ? 'Pass' : 'Reject'}</span>
          <label>PTY</label><span>${ssh.pty ? 'Pass' : 'Reject'}</span>
          <label>Environment</label><span>${ssh.environment ? 'Pass' : 'Reject'}</span>
          <label>Local forwarding</label><span>${ssh.localForward ? 'Pass' : 'Reject'}</span>
          <label>Remote forwarding</label><span>${ssh.remoteForward ? 'Pass' : 'Reject'}</span>
          <label>X11 forwarding</label><span>${ssh.x11 ? 'Pass' : 'Reject'}</span>
          <label>Agent forwarding</label><span>${ssh.agent ? 'Pass' : 'Reject'}</span>
        ` : dns ? html`
          <label>Match request ID</label><span>${dns.matchRequestId ? 'Enabled' : 'Disabled'}</span>
          <label>Randomize upstream ID</label><span>${dns.randomizeId ? 'Enabled' : 'Disabled'}</span>
          <label>Cached responses</label><span>${dns.cachedResponses ? 'Enabled' : 'Disabled'}</span>
        ` : html`<label>Value exposure</label><span>Metadata only</span>`}
      </div>
      ${routing || tls || detection || content || ssh || dns ? nothing : html`<div class="privacy-note section">
        Profile values remain inside the GUI core until a typed, redacted editor is available.
      </div>`}
      ${tls ? html`<div class="privacy-note section">
        SNI bypass values stay inside the GUI core; only their bounded count is exposed.
      </div>` : nothing}
      ${content ? html`<div class="privacy-note section">
        Content rule patterns, replacements, and session filters stay inside the GUI core.
      </div>` : nothing}
      ${ssh ? html`<div class="privacy-note section">
        The private host-key path stays inside the GUI core.
      </div>` : nothing}
      ${this.renderObjectUsage(profile)}
    `;
  }

  private renderObjectUsage(object: PortObject | ProtocolObject | ProfileObject) {
    return html`
      <div class="section">
        <h3>Impact</h3>
        <div class="impact">This shared object is used by ${object.usedBy.length} configuration entries.</div>
        <ul class="usage">
          ${object.usedBy.map(reference => html`<li><strong>${reference.name}</strong> · ${reference.kind}</li>`)}
        </ul>
      </div>
    `;
  }

  private renderDrawerBody(entry: DrawerEntry) {
    if (entry.kind === 'policy') return this.renderPolicyEditor(entry);
    if (entry.kind === 'address') return this.renderAddressEditor(entry);
    if (entry.kind === 'port') return this.renderPortEditor(entry);
    if (entry.kind === 'protocol') return this.renderProtocolEditor(entry);
    return this.renderProfileEditor(entry);
  }

  private renderDrawer(entry: DrawerEntry, index: number) {
    const saved = this.draftObjects.has(`${entry.kind}:${entry.id}`);
    const editLabel = `Edit ${entry.title}`;
    const closeLabel = `Close ${entry.title}`;
    const visibleDepth = Math.min(index, 5);
    const active = index === this.drawers.length - 1;
    const readOnly = this.snapshot?.source === 'live' && !this.configWriteAvailable;
    return html`
      <section class="drawer ${this.focusMode && active ? 'focus-mode' : ''}"
        data-depth=${visibleDepth} role="dialog" aria-modal=${active ? 'true' : 'false'}
        aria-hidden=${active ? nothing : 'true'} aria-label=${editLabel} tabindex="-1" ?inert=${!active}>
        <header class="drawer-head">
          <div class="drawer-title"><small>Edit ${entry.kind}</small><h2>${entry.title}</h2></div>
          ${active ? html`
            <button class="icon-button" type="button"
              aria-label=${this.focusMode ? 'Exit focus mode' : 'Enter focus mode'}
              title=${this.focusMode ? 'Exit focus mode' : 'Focus mode'}
              @click=${() => { this.focusMode = !this.focusMode; }}>⛶</button>
          ` : nothing}
          <button class="icon-button" type="button" aria-label=${closeLabel} @click=${() => this.closeDrawer(index)}>×</button>
        </header>
        <div class="drawer-body">
          ${this.renderDrawerBody(entry)}
        </div>
        <footer class="drawer-foot">
          <span class="validation">${readOnly ? 'Read-only runtime view' : saved ? 'Saved to draft' : 'Validation ready'}</span>
          <button class="secondary" type="button" @click=${() => this.closeDrawer(index)}>Cancel</button>
          <button class="primary" type="button" ?disabled=${readOnly} @click=${() => this.saveToDraft(entry)}>Save to draft</button>
        </footer>
      </section>
    `;
  }

  protected render() {
    if (this.loadingError) return html`<div class="error" role="alert">${this.loadingError}</div>`;
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
            <input class="search" type="search" aria-label="Search" placeholder="Search policies and objects" />
          </header>
          <div class="workspace">
            <div class="content-layer" ?inert=${this.drawers.length > 0}>${this.renderContent()}</div>
            ${this.drawers.map((entry, index) => this.renderDrawer(entry, index))}
          </div>
        </main>
        <footer class="statusbar">
          <span class="system-state ${this.systemStatus.core === 'online' ? 'success' : this.systemStatus.core === 'offline' ? 'danger' : 'warning'}">
            ● Core: ${displayState(this.systemStatus.core)}
          </span>
          <span class="system-state ${statusTone(this.systemStatus)}" title=${this.systemStatusTitle()} aria-live="polite">
            ● Smithproxy: ${displayState(this.systemStatus.smithproxy)}
          </span>
          <span class=${this.draftObjects.size ? 'draft' : ''}>Draft: ${this.draftObjects.size} changes</span>
          <span title=${this.configError ?? this.snapshot?.detail ?? ''}>
            Config: ${this.snapshot?.source === 'live'
              ? displayState(this.snapshot.state)
              : this.configError ? 'Preview · live unavailable' : this.snapshot ? 'Preview' : 'Loading'}
          </span>
          <span>API: ${this.apiVersion}</span><span class="spacer"></span>
          <span>Revision ${this.snapshot?.revision ?? 'runtime'}</span>
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
