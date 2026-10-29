import {LitElement, css, html, nothing} from 'lit';
import {customElement, property, state} from 'lit/decorators.js';
import {ApiConfigClient} from './api/config-client';
import {DraftClient, type DraftChange, type DraftScalar, type DraftSnapshot} from './api/draft-client';
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
  type EventSnapshot,
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

const initialEvents: EventSnapshot = {
  source: 'gui-core',
  smithproxyEventsAvailable: false,
  events: [],
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
  @state() private operationalEvents: EventSnapshot = initialEvents;
  @state() private eventsError: string | undefined;
  @state() private focusMode = false;
  @state() private configWriteAvailable = false;
  @state() private draftAvailable = false;
  @state() private draftVersion = 0;
  @state() private draftChangeCount = 0;
  @state() private workspaceDraft?: DraftSnapshot;
  @state() private discardDraftArmed = false;
  @state() private draftSaving = false;
  @state() private draftError: string | undefined;
  @state() private configError: string | undefined;
  @state() private searchQuery = '';

  private readonly previewClient = new FakeConfigClient();
  private readonly drawerStore = new DrawerStore();
  private runtime?: RuntimeConfig;
  private systemClient?: SystemClient;
  private draftClient?: DraftClient;
  private systemProbeTimer: number | undefined;
  private systemProbeInFlight = false;
  private systemProbePending = false;
  private drawerHistoryDepth = 0;
  private drawerOrigins: HTMLElement[] = [];
  private pendingReturnFocus: HTMLElement | undefined;
  private searchReturnSection = 'Dashboard';

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
    .metrics-message { padding: 11px 13px; border: 1px solid var(--app-border); border-radius: 3px; color: var(--app-muted); }
    .privacy-note { padding: 10px 13px; border-left: 3px solid var(--app-success); background: var(--app-success-bg); color: var(--app-muted); }
    .origin-note { padding: 9px 11px; border-left: 3px solid var(--app-warning); background: var(--app-warning-bg); color: var(--app-muted); font-size: 12px; }
    .origin-note strong { color: var(--app-text); }
    .event-list { display: grid; overflow: hidden; border: 1px solid var(--app-border); border-radius: 4px; background: var(--app-surface); }
    .event-row { display: grid; grid-template-columns: 150px 78px minmax(180px, 1fr) 100px; gap: 14px; align-items: center; padding: 12px 14px; border-bottom: 1px solid var(--app-border); }
    .event-row:last-child { border-bottom: 0; }
    .event-time, .event-source { color: var(--app-muted); font-size: 12px; }
    .event-severity { font-size: 12px; font-weight: 700; letter-spacing: .03em; text-transform: uppercase; }
    .event-severity.info { color: var(--app-success); }
    .event-severity.notice, .event-severity.warning { color: var(--app-warning); }
    .event-severity.error { color: var(--app-danger); }
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
    .draft-row { display: grid; grid-template-columns: minmax(220px, .8fr) minmax(260px, 1.2fr); gap: 18px; padding: 12px 14px; border-bottom: 1px solid var(--app-border); }
    .draft-row:last-child { border-bottom: 0; }
    .draft-row.heading { color: var(--app-muted); font-size: 12px; }
    .draft-path { overflow-wrap: anywhere; color: var(--app-muted); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; }
    .draft-value { overflow-wrap: anywhere; }
    .danger-button { border-color: var(--app-danger); background: transparent; color: var(--app-danger); }
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
      .trend-grid { grid-template-columns: 1fr; }
      .system-grid { grid-template-columns: 1fr; }
      .form-grid.wide-form-grid { grid-template-columns: minmax(120px, .35fr) minmax(220px, 1fr); max-width: 920px; }
    }

    @media (max-width: 620px) {
      .shell { grid-template: 52px minmax(0, 1fr) 30px / minmax(0, 1fr); }
      .sidebar { grid-row: 1; display: flex; align-items: center; overflow-x: auto; padding: 6px 8px; border-right: 0; border-bottom: 1px solid var(--app-border); }
      .brand { margin: 0 10px 0 0; }
      nav { display: flex; }
      nav button { width: 42px; padding: 8px; }
      .main { grid-row: 2; grid-template-rows: 94px minmax(0, 1fr); }
      .topbar { display: grid; grid-template: auto auto / minmax(0, 1fr) auto; gap: 5px 8px; padding: 8px 12px; }
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
      .statusbar span:nth-of-type(n + 3) { display: none; }
      .metric-grid { grid-template-columns: 1fr; }
      .object-row { grid-template-columns: minmax(120px, 1fr) 90px; }
      .object-row > :nth-child(3), .object-row > :nth-child(4) { display: none; }
      .event-row { grid-template-columns: 110px 66px minmax(120px, 1fr); }
      .draft-row { grid-template-columns: 1fr; gap: 5px; }
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
      this.draftClient = new DraftClient(this.runtime.apiBase);
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
      try {
        this.operationalEvents = await this.systemClient.recentEvents();
        this.eventsError = undefined;
      } catch (error) {
        this.eventsError = error instanceof Error ? error.message : 'Operational events are unavailable.';
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
      this.draftAvailable = capabilities.features.drafts;
      if (capabilities.features.configRead && this.runtime && this.snapshot?.source !== 'live') {
        try {
          this.snapshot = await new ApiConfigClient(this.runtime.apiBase).loadSnapshot();
          this.configError = undefined;
          this.restoreDrawerRoute();
        } catch (error) {
          this.configError = error instanceof Error ? error.message : 'Live configuration is unavailable.';
        }
      }
      if (this.draftAvailable) await this.loadDraft();
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

  private applyDraft(snapshot: DraftSnapshot): void {
    this.workspaceDraft = snapshot;
    this.draftVersion = snapshot.version;
    this.draftChangeCount = snapshot.changes.length;
    if (snapshot.changes.length === 0) this.discardDraftArmed = false;
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
        if (item) objects.add(`profile:${item.id}`);
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
    this.draftObjects = objects;
  }

  private async loadDraft(): Promise<void> {
    if (!this.draftClient) return;
    try {
      this.applyDraft(await this.draftClient.load());
      this.draftError = undefined;
    } catch (error) {
      this.draftError = error instanceof Error ? error.message : 'Workspace draft is unavailable.';
    }
  }

  private async discardDraft(): Promise<void> {
    if (!this.draftAvailable || !this.draftClient || this.draftChangeCount === 0) return;
    if (!this.discardDraftArmed) {
      this.discardDraftArmed = true;
      return;
    }
    this.draftSaving = true;
    this.draftError = undefined;
    try {
      this.applyDraft(await this.draftClient.clear(this.draftVersion));
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Workspace draft could not be discarded.';
      await this.loadDraft();
      this.draftError = message;
    } finally {
      this.draftSaving = false;
      this.discardDraftArmed = false;
    }
  }

  private draftValueSummary(path: string, value: DraftScalar): string {
    const sensitivePaths = new Set([
      'settings.webhook.url', 'settings.syslog_server', 'settings.write_payload_dir',
      'settings.log_file', 'settings.sslkeylog_file', 'settings.certs_path',
      'settings.certs_ca_key_password', 'settings.ca_bundle_path', 'settings.messages_dir',
      'settings.write_payload_file_prefix', 'settings.write_payload_file_suffix',
      'settings.cli.enable_password', 'settings.web_rating.wot_key', 'settings.http_api.keys',
      'captures.local.dir', 'captures.local.file_prefix', 'captures.local.file_suffix',
      'captures.remote.tun_dst', 'captures.remote.bind_interface',
    ]);
    const indexedSensitivePath =
      (path.startsWith('ssh_profiles.[') && path.endsWith('].host_key')) ||
      (path.startsWith('script_profiles.[') && path.endsWith('].script-file')) ||
      (path.startsWith('tls_profiles.[') && path.endsWith('].sni_filter_bypass')) ||
      (path.startsWith('content_profiles.[') && path.endsWith('].rules_session_filter')) ||
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

  private openAuthority(id: string, origin?: HTMLElement): void {
    const authority = this.snapshot?.securityAssets?.certificateAuthorities.find(item => item.id === id);
    if (!authority) return;
    this.openObjectDrawer({kind: 'authority', id: authority.id, title: authority.name}, origin);
  }

  private openSignature(id: string, origin?: HTMLElement): void {
    const signature = this.snapshot?.securityAssets?.signatures.find(item => item.id === id);
    if (!signature) return;
    this.openObjectDrawer({kind: 'signature', id: signature.id, title: signature.name}, origin);
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
    if (this.drawers[0] && ['settings', 'captures', 'authority', 'signature', 'signature-flow']
      .includes(this.drawers[0].kind)) {
      this.activeSection = 'System';
    }
    else if (this.drawers[0] && this.drawers[0].kind !== 'policy') this.activeSection = 'Objects';
    this.focusMode = false;
    void this.updateComplete.then(() => this.focusActiveDrawer());
  }

  private drawerCandidate(entry: Pick<DrawerEntry, 'kind' | 'id'>) {
    if (!this.snapshot) return undefined;
    if (entry.kind === 'policy') return this.snapshot.policies.find(item => item.id === entry.id);
    if (entry.kind === 'address') return this.snapshot.addresses.find(item => item.id === entry.id);
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

  private async saveToDraft(entry: DrawerEntry): Promise<void> {
    if (this.snapshot?.source !== 'live') {
      this.draftObjects = new Set(this.draftObjects).add(`${entry.kind}:${entry.id}`);
      this.draftChangeCount = this.draftObjects.size;
      return;
    }
    if (!this.draftAvailable || !this.draftClient) return;
    const changes = this.draftChanges(entry);
    if (!changes) return;
    this.draftSaving = true;
    this.draftError = undefined;
    try {
      this.applyDraft(await this.draftClient.upsertMany(this.draftVersion, changes));
      if (entry.kind === 'settings' || entry.kind === 'captures' || entry.kind === 'profile' ||
          entry.kind === 'authority' || entry.kind === 'signature-flow') {
        this.renderRoot.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(
          '[id*="-write-"][id$="-value"], #settings-api-keys-value',
        ).forEach(input => { input.value = ''; });
        this.renderRoot.querySelectorAll<HTMLSelectElement>(
          '[id*="-write-"][id$="-mode"], #settings-api-keys-mode',
        ).forEach(select => { select.value = 'unchanged'; });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Draft change could not be saved.';
      await this.loadDraft();
      this.draftError = message;
    } finally {
      this.draftSaving = false;
    }
  }

  private draftChanges(entry: DrawerEntry): ReadonlyArray<DraftChange> | undefined {
    if (!this.snapshot) return undefined;
    if (entry.kind === 'settings') return this.systemSettingsDraftChanges();
    if (entry.kind === 'captures') return this.captureSettingsDraftChanges();
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
      const group = input('group');
      const enables = input('enables');
      const engine = input('engine');
      if (index < 0 || !category || !name || !side || !group || !enables || !engine ||
          !['client', 'server'].includes(side.value)) return undefined;
      const values: [string, string, string, string, string] = [
        category.value.trim(), name.value.trim(), group.value.trim(),
        enables.value.trim(), engine.value.trim(),
      ];
      if (values[1].length === 0 || values.some(value => value.length > 128 ||
          /[\u0000-\u001f\u007f]/u.test(value))) {
        this.draftError = 'Signature metadata must use bounded printable values and include a name.';
        return undefined;
      }
      const base = `${signature.kind}_signatures.[${index}]`;
      return [
        {path: `${base}.cat`, value: values[0]},
        {path: `${base}.name`, value: values[1]},
        {path: `${base}.side`, value: side.value},
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
      const validList = (values: ReadonlyArray<string>) => values.length <= 256 &&
        values.every(value => value.length <= 128) && new Set(values).size === values.length;
      if (name.value.trim().length === 0 || name.value.trim().length > 128 ||
          action.value.trim().length === 0 || action.value.trim().length > 32 ||
          protocol.value.trim().length === 0 || protocol.value.trim().length > 128 ||
          sourceValues.length === 0 || destinations.length === 0 ||
          ![sourceValues, sourcePortValues, destinations, destinationPortValues, featureValues].every(validList) ||
          [nat, ...references.values()].some(value => value!.value.trim().length > 128)) {
        this.draftError = 'Policy fields and unique bounded references are required.';
        return undefined;
      }
      return [
        {path: `policy.[${index}].name`, value: name.value.trim()},
        {path: `policy.[${index}].disabled`, value: !enabled.checked},
        {path: `policy.[${index}].proto`, value: protocol.value.trim()},
        {path: `policy.[${index}].src`, value: sourceValues},
        {path: `policy.[${index}].sport`, value: sourcePortValues},
        {path: `policy.[${index}].dst`, value: destinations},
        {path: `policy.[${index}].dport`, value: destinationPortValues},
        {path: `policy.[${index}].features`, value: featureValues},
        ...(this.snapshot.valueOrigins.find(item => item.path === `policy.[${index}].action`)?.editable === false
          ? [] : [{path: `policy.[${index}].action`, value: action.value.trim()}]),
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
      if (name.value.trim().length === 0 || value.value.trim().length === 0 ||
          !['cidr', 'fqdn', 'host', 'subnet', 'range'].includes(type.value)) {
        this.draftError = 'Name and address value are required.';
        return undefined;
      }
      return [
        {path: `address_objects.[${index}].name`, value: name.value.trim()},
        {path: `address_objects.[${index}].type`, value: type.value},
        {path: `address_objects.[${index}].value`, value: value.value.trim()},
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
      if (name.value.trim().length === 0 || !Number.isInteger(startValue) || !Number.isInteger(endValue) ||
          startValue < 0 || endValue > 65535 || startValue > endValue) {
        this.draftError = 'Name and a valid port range from 0 to 65535 are required.';
        return undefined;
      }
      return [
        {path: `port_objects.[${index}].name`, value: name.value.trim()},
        {path: `port_objects.[${index}].start`, value: startValue},
        {path: `port_objects.[${index}].end`, value: endValue},
      ];
    }
    if (entry.kind === 'protocol') {
      const index = this.snapshot.protocols.findIndex(item => item.id === entry.id);
      const name = this.renderRoot.querySelector<HTMLInputElement>(`#protocol-name-${entry.id}`);
      const number = this.renderRoot.querySelector<HTMLInputElement>(`#protocol-number-${entry.id}`);
      const numberValue = number?.valueAsNumber ?? Number.NaN;
      if (index < 0 || !name || !number) return undefined;
      if (name.value.trim().length === 0 || !Number.isInteger(numberValue) ||
          numberValue < 0 || numberValue > 255) {
        this.draftError = 'Name and a valid IP protocol number from 0 to 255 are required.';
        return undefined;
      }
      return [
        {path: `proto_objects.[${index}].name`, value: name.value.trim()},
        {path: `proto_objects.[${index}].id`, value: numberValue},
      ];
    }
    if (entry.kind === 'profile') {
      const profile = this.snapshot.profiles.find(item => item.id === entry.id);
      const name = this.renderRoot.querySelector<HTMLInputElement>(`#profile-name-${entry.id}`);
      if (!profile || !name || name.value.trim().length === 0 || name.value.trim().length > 128) {
        this.draftError = 'A profile name up to 128 characters is required.';
        return undefined;
      }
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
          {path: `routing.[${index}].name`, value: name.value.trim()},
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
          ['allow_untrusted_issuers', 'allow-untrusted'],
          ['allow_invalid_certs', 'allow-invalid'],
          ['allow_self_signed', 'allow-self-signed'],
          ['ct_enable', 'certificate-transparency'],
          ['ocsp_stapling', 'ocsp-stapling'],
          ['alpn_block', 'block-alpn'],
          ['only_custom_certs', 'custom-only'],
          ['no_fallback_bypass', 'no-fallback'],
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
        const clientAction = this.renderRoot.querySelector<HTMLSelectElement>(`#tls-client-action-${entry.id}`);
        const alerts = this.renderRoot.querySelector<HTMLSelectElement>(`#tls-alerts-${entry.id}`);
        const bypassMode = this.renderRoot.querySelector<HTMLSelectElement>(`#tls-write-sni-${entry.id}-mode`);
        const bypassInput = this.renderRoot.querySelector<HTMLTextAreaElement>(`#tls-write-sni-${entry.id}-value`);
        const helloValue = helloTimeout?.valueAsNumber ?? Number.NaN;
        const handshakeValue = handshakeTimeout?.valueAsNumber ?? Number.NaN;
        if (!helloTimeout || !handshakeTimeout || !clientAction || !alerts || !bypassMode || !bypassInput ||
            !Number.isInteger(helloValue) || helloValue < 1 || helloValue > 3600000 ||
            !Number.isInteger(handshakeValue) || handshakeValue < 1 || handshakeValue > 3600000 ||
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
          {path: `tls_profiles.[${index}].name`, value: name.value.trim()},
          ...booleanChanges,
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
          {path: `content_profiles.[${index}].name`, value: name.value.trim()},
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
          {path: `ssh_profiles.[${index}].name`, value: name.value.trim()},
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
          {path: `script_profiles.[${index}].name`, value: name.value.trim()},
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
          {path: `auth_profiles.[${index}].name`, value: name.value.trim()},
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
          {path: `detection_profiles.[${index}].name`, value: name.value.trim()},
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
          {path: `alg_dns_profiles.[${index}].name`, value: name.value.trim()},
          {path: `alg_dns_profiles.[${index}].match_request_id`, value: match.value === 'true'},
          {path: `alg_dns_profiles.[${index}].randomize_id`, value: randomize.value === 'true'},
          {path: `alg_dns_profiles.[${index}].cached_responses`, value: cached.value === 'true'},
        ];
      }
    }
    return undefined;
  }

  private systemSettingsDraftChanges(): ReadonlyArray<DraftChange> | undefined {
    const booleanFields = [
      ['accept_tproxy', 'accept-tproxy'], ['accept_redirect', 'accept-redirect'],
      ['accept_socks', 'accept-socks'], ['accept_http_connect', 'accept-http-connect'],
      ['accept_api', 'accept-api'], ['policy_fail_open', 'policy-fail-open'],
      ['policy_access_request_fail_open', 'access-fail-open'],
      ['ssl_autodetect', 'tls-autodetect'], ['ssl_autodetect_harder', 'tls-autodetect-harder'],
      ['ssl_use_ktls', 'kernel-tls'], ['http_api.loopback_only', 'api-loopback'],
      ['http_api.pam_login', 'api-pam'], ['http_api.allow_api_header', 'api-header'],
      ['webhook.enabled', 'webhook-enabled'], ['webhook.tls_verify', 'webhook-tls'],
      ['webhook.sift', 'webhook-sift'], ['webhook.api_override', 'webhook-override'],
      ['default_write_payload', 'logging-default-payload'], ['log_console', 'logging-console'],
      ['socks.async_dns', 'aux-socks-async-dns'],
    ] as const;
    const changes: DraftChange[] = [];
    for (const [path, id] of booleanFields) {
      const select = this.renderRoot.querySelector<HTMLSelectElement>(`#settings-${id}`);
      if (!select || (select.value !== 'true' && select.value !== 'false')) return undefined;
      changes.push({path: `settings.${path}`, value: select.value === 'true'});
    }
    const workerFields = [
      ['plaintext_workers', 'plaintext'], ['ssl_workers', 'tls'], ['udp_workers', 'udp'],
      ['dtls_workers', 'dtls'], ['quic_workers', 'quic'], ['socks_workers', 'socks'],
      ['http_connect_workers', 'http-connect'],
    ] as const;
    for (const [path, id] of workerFields) {
      const input = this.renderRoot.querySelector<HTMLInputElement>(`#settings-worker-${id}`);
      const value = input?.valueAsNumber ?? Number.NaN;
      if (!input || !Number.isInteger(value) || value < -1 || value > 4096) {
        this.draftError = 'Worker counts must be integers from -1 to 4096.';
        return undefined;
      }
      changes.push({path: `settings.${path}`, value});
    }
    const numericFields = [
      ['plaintext_port', 'port-plaintext', 65535], ['ssl_port', 'port-tls', 65535],
      ['udp_port', 'port-udp', 65535], ['quic_port', 'port-quic', 65535],
      ['http_connect_port', 'port-http-connect', 65535],
      ['ssl_ocsp_status_ttl', 'ocsp-status-ttl', 31536000],
      ['ssl_crl_status_ttl', 'crl-status-ttl', 31536000],
      ['write_pcap_single_quota', 'logging-pcap-quota', 1048576],
      ['log_level', 'logging-level', 10], ['syslog_port', 'logging-syslog-port', 65535],
      ['syslog_facility', 'logging-syslog-facility', 23],
      ['syslog_level', 'logging-syslog-level', 10],
      ['cli.port', 'aux-cli-port', 65535],
    ] as const;
    for (const [path, id, maximum] of numericFields) {
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
      ['ca_bundle_path', 'ca-bundle-path', 'path'], ['messages_dir', 'messages-directory', 'path'],
      ['write_payload_file_prefix', 'payload-prefix', 'filename'],
      ['write_payload_file_suffix', 'payload-suffix', 'filename'],
      ['cli.enable_password', 'cli-password', 'secret'],
      ['web_rating.wot_key', 'web-rating-key', 'secret'],
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
      const debugFields = [
        ['log_data_crc', 'data-crc'], ['log_sockets', 'sockets'],
        ['log_online_cx_name', 'online-name'], ['log_srclines', 'source-lines'],
        ['log_srclines_always', 'source-lines-always'],
      ] as const;
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
    const booleanFields = [
      ['local.enabled', 'local-enabled'], ['remote.enabled', 'remote-enabled'],
      ['options.calculate_checksums', 'checksums'],
    ] as const;
    const changes: DraftChange[] = [];
    for (const [path, id] of booleanFields) {
      const select = this.renderRoot.querySelector<HTMLSelectElement>(`#captures-${id}`);
      if (!select || (select.value !== 'true' && select.value !== 'false')) return undefined;
      changes.push({path: `captures.${path}`, value: select.value === 'true'});
    }
    const format = this.renderRoot.querySelector<HTMLSelectElement>('#captures-local-format');
    const greFormat = this.renderRoot.querySelector<HTMLSelectElement>('#captures-gre-format');
    const quota = this.renderRoot.querySelector<HTMLInputElement>('#captures-local-quota');
    const ttl = this.renderRoot.querySelector<HTMLInputElement>('#captures-remote-ttl');
    const quotaValue = quota?.valueAsNumber ?? Number.NaN;
    const ttlValue = ttl?.valueAsNumber ?? Number.NaN;
    if (!format || !greFormat || !quota || !ttl ||
        !['pcap_single', 'pcap', 'smcap'].includes(format.value) ||
        !['traffic', 'pcapng'].includes(greFormat.value) ||
        !Number.isInteger(quotaValue) || quotaValue < 0 || quotaValue > 1048576 ||
        !Number.isInteger(ttlValue) || ttlValue < 0 || ttlValue > 255) {
      this.draftError = 'Capture format, quota, or tunnel TTL is invalid.';
      return undefined;
    }
    changes.push(
      {path: 'captures.local.format', value: format.value},
      {path: 'captures.local.pcap_quota', value: quotaValue},
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
      this.closeDrawer(this.drawers.length - 1);
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
    return html`
      <div class="content">
        <div class="section-head">
          <div>
            <h2>Workspace draft</h2>
            <p>Version ${this.draftVersion} · ${changes.length} pending changes</p>
          </div>
          <button class="secondary danger-button" type="button"
            ?disabled=${changes.length === 0 || this.draftSaving}
            @click=${() => this.discardDraft()}>
            ${this.draftSaving
              ? 'Discarding…'
              : this.discardDraftArmed
                ? `Confirm discard ${changes.length} changes`
                : 'Discard draft'}
          </button>
        </div>
        ${this.draftError ? html`<div class="error" role="alert">${this.draftError}</div>` : nothing}
        ${changes.length === 0 ? html`
          <div class="empty-state">
            <h2>No pending changes</h2>
            <p>Edits from policy and referenced-object drawers will appear here before validation and commit.</p>
          </div>
        ` : html`
          <div class="table" role="table" aria-label="Pending draft changes">
            <div class="draft-row heading" role="row">
              <span role="columnheader">Configuration path</span>
              <span role="columnheader">Draft value</span>
            </div>
            ${changes.map(change => html`
              <div class="draft-row" role="row">
                <span class="draft-path" role="cell">${change.path}</span>
                <span class="draft-value" role="cell">${this.draftValueSummary(change.path, change.value)}</span>
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

  private updateSearch(value: string): void {
    const query = value.slice(0, 128);
    if (!this.searchQuery && query) this.searchReturnSection = this.activeSection;
    this.searchQuery = query;
    this.activeSection = query ? 'Search' : this.searchReturnSection;
  }

  private searchMatches(values: ReadonlyArray<string | number>, query: string): boolean {
    return values.some(value => String(value).toLocaleLowerCase().includes(query));
  }

  private renderSearchResults() {
    const query = this.searchQuery.trim().toLocaleLowerCase();
    if (!query || !this.snapshot) return html`<div class="empty-state"><h2>Search</h2><p>Enter a policy or object name.</p></div>`;
    const policies = this.snapshot.policies.filter(policy => this.searchMatches([
      policy.name, policy.action, policy.protocol, ...policy.sources.map(item => item.name),
      ...policy.sourcePorts, ...policy.destinations.map(item => item.name), ...policy.destinationPorts,
      ...policy.features, policy.nat, policy.routing, policy.tlsProfile, policy.sshProfile,
      policy.detectionProfile, policy.contentProfile, policy.authProfile, policy.dnsProfile,
      policy.scriptProfile,
    ], query));
    const addresses = this.snapshot.addresses.filter(item => this.searchMatches([item.name, item.type, item.value], query));
    const ports = this.snapshot.ports.filter(item => this.searchMatches([item.name, item.start, item.end], query));
    const protocols = this.snapshot.protocols.filter(item => this.searchMatches([item.name, item.number], query));
    const profiles = this.snapshot.profiles.filter(item => this.searchMatches([item.name, item.type], query));
    const count = policies.length + addresses.length + ports.length + protocols.length + profiles.length;
    const row = (kind: string, name: string, detail: string, open: (origin: HTMLElement) => void) => html`
      <button class="row object-row" type="button"
        @click=${(event: MouseEvent) => open(event.currentTarget as HTMLElement)}>
        <strong>${name}</strong><span class="action">${kind}</span><span class="object-value">${detail}</span><span>Open</span>
      </button>`;
    return html`
      <div class="content">
        <div class="section-head"><div><h2>Search results</h2><p>${count} matches for “${this.searchQuery.trim()}”</p></div></div>
        ${count === 0 ? html`<div class="empty-state"><h2>No matches</h2><p>Try a name, type, value, action, or reference.</p></div>` : html`
          <div class="table" role="group" aria-label="Search results">
            <div class="row object-row heading" aria-hidden="true"><span>Name</span><span>Kind</span><span>Match context</span><span></span></div>
            ${policies.map(item => row('Policy', item.name, item.action, origin => this.openPolicy(item, origin)))}
            ${addresses.map(item => row('Address', item.name, `${item.type} · ${item.value}`, origin => this.openAddress(item.id, origin)))}
            ${ports.map(item => row('Port', item.name, item.start === item.end ? String(item.start) : `${item.start}–${item.end}`, origin => this.openPort(item.id, origin)))}
            ${protocols.map(item => row('Protocol', item.name, String(item.number), origin => this.openProtocol(item.id, origin)))}
            ${profiles.map(item => row('Profile', item.name, item.type, origin => this.openProfile(item.id, origin)))}
          </div>`}
      </div>`;
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
                <span>${profile.routing || profile.tls || profile.detection || profile.content || profile.ssh ||
                  profile.dns || profile.script || profile.authentication
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

  private sampleAgeLabel(value: number | null): string {
    if (value === null) return 'Never sampled';
    const seconds = Math.max(0, Math.floor((Date.now() - value) / 1000));
    if (seconds < 2) return 'Now';
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    return minutes < 60 ? `${minutes}m ago` : `${Math.floor(minutes / 60)}h ago`;
  }

  private renderOperationalHealth() {
    const items = [
      {name: 'Control plane', state: this.systemStatus.smithproxy, checked: this.systemStatus.checkedAtUnixMs},
      {name: 'Listener metrics', state: this.runtimeMetrics.state, checked: this.runtimeMetrics.checkedAtUnixMs},
      {name: 'Session activity', state: this.sessionActivity.state, checked: this.sessionActivity.checkedAtUnixMs},
      {name: 'TLS cache', state: this.tlsCache.state, checked: this.tlsCache.checkedAtUnixMs},
      {name: 'Neighborhood', state: this.neighbors.state, checked: this.neighbors.checkedAtUnixMs},
      {name: 'Configuration', state: this.snapshot?.state ?? 'starting', checked: this.snapshot?.checkedAtUnixMs ?? null},
    ];
    return html`
      <section class="runtime-summary" aria-label="Operational health matrix">
        <div class="runtime-heading">
          <div><h3>Operational health</h3><p>Current state and freshness across GUI core data planes</p></div>
        </div>
        <div class="card-grid">
          ${items.map(item => {
            const tone = item.state === 'ready' ? 'success' :
              ['unreachable', 'unauthorized', 'error', 'unavailable'].includes(item.state) ? 'danger' : 'warning';
            return html`<article class="domain-card">
              <header><div><h3>${item.name}</h3><p>${this.sampleAgeLabel(item.checked)}</p></div>
                <span class="runtime-state ${tone}">● ${displayState(item.state)}</span>
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
        ${this.renderOperationalHealth()}
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
          ${this.renderProbeAnalysis()}
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
        ${this.renderOperationalHealth()}
        ${this.renderProbeAnalysis()}
        ${this.renderRuntimeSummary()}
        ${this.renderRuntimeHistory()}
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
    const settings = this.snapshot?.settings;
    const debug = this.snapshot?.debug;
    const captures = this.snapshot?.captures;
    const securityAssets = this.snapshot?.securityAssets;
    const workers = (value: number) => value === -1 ? 'Disabled' : String(value);
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
          <article class="domain-card">
            <header><div><h3>Augment overlays</h3><p>Persistent and effective value provenance</p></div></header>
            <dl>
              <dt>Capability</dt><dd>${this.snapshot?.augmentSupport ? 'Available' : 'Not advertised'}</dd>
              <dt>Tracked values</dt><dd>${this.snapshot?.valueOrigins.length ?? 0}</dd>
              <dt>Editing target</dt><dd>Persistent config</dd>
            </dl>
          </article>
          ${settings ? html`
            <article class="domain-card">
              <header><div><h3>Traffic admission</h3><p>Runtime listener and failure policy</p></div>
                <button class="secondary" type="button" @click=${(event: Event) => this.openSystemDrawer('settings', event.currentTarget as HTMLElement)}>Edit</button>
              </header>
              <dl>
                <dt>TPROXY / REDIRECT</dt><dd>${settings.acceptTproxy ? 'On' : 'Off'} / ${settings.acceptRedirect ? 'On' : 'Off'}</dd>
                <dt>SOCKS / CONNECT</dt><dd>${settings.acceptSocks ? 'On' : 'Off'} / ${settings.acceptHttpConnect ? 'On' : 'Off'}</dd>
                <dt>Policy failure</dt><dd>${settings.policyFailOpen ? 'Fail open' : 'Fail closed'}</dd>
                <dt>Access request failure</dt><dd>${settings.accessRequestFailOpen ? 'Fail open' : 'Fail closed'}</dd>
              </dl>
            </article>
            <article class="domain-card">
              <header><div><h3>Worker pools</h3><p>Configured runtime concurrency</p></div></header>
              <dl>
                <dt>Plaintext / TLS</dt><dd>${workers(settings.workers.plaintext)} / ${workers(settings.workers.tls)}</dd>
                <dt>UDP / DTLS / QUIC</dt><dd>${workers(settings.workers.udp)} / ${workers(settings.workers.dtls)} / ${workers(settings.workers.quic)}</dd>
                <dt>SOCKS / CONNECT</dt><dd>${workers(settings.workers.socks)} / ${workers(settings.workers.httpConnect)}</dd>
                <dt>TLS autodetect</dt><dd>${settings.tlsAutodetect ? 'Enabled' : 'Disabled'}</dd>
                <dt>Kernel TLS</dt><dd>${settings.kernelTls ? 'Requested' : 'Disabled'}</dd>
              </dl>
            </article>
            <article class="domain-card">
              <header><div><h3>Listener endpoints</h3><p>Configured local ports and certificate status caches</p></div></header>
              <dl>
                <dt>Plaintext / TLS</dt><dd>${settings.ports.plaintext} / ${settings.ports.tls}</dd>
                <dt>UDP / QUIC</dt><dd>${settings.ports.udp} / ${settings.ports.quic}</dd>
                <dt>HTTP CONNECT</dt><dd>${settings.ports.httpConnect}</dd>
                <dt>OCSP status TTL</dt><dd>${settings.ocspStatusTtl.toLocaleString()} s</dd>
                <dt>CRL status TTL</dt><dd>${settings.crlStatusTtl.toLocaleString()} s</dd>
              </dl>
            </article>
            <article class="domain-card">
              <header><div><h3>Logging and payloads</h3><p>Destinations stay redacted</p></div></header>
              <dl>
                <dt>Log level / console</dt><dd>${settings.logging.level} / ${settings.logging.console ? 'On' : 'Off'}</dd>
                <dt>Log file</dt><dd>${settings.logging.fileConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>TLS key log</dt><dd>${settings.logging.sslKeyFileConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>Default payload capture</dt><dd>${settings.logging.defaultWritePayload ? 'Enabled' : 'Disabled'}</dd>
                <dt>Payload directory</dt><dd>${settings.logging.payloadDirectoryConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>Single PCAP quota</dt><dd>${settings.logging.pcapSingleQuota.toLocaleString()}</dd>
                <dt>Syslog</dt><dd>${settings.logging.syslogServerConfigured ? `Configured · IPv${settings.logging.syslogFamily}` : 'Not configured'}</dd>
                <dt>Syslog port / facility / level</dt><dd>${settings.logging.syslogPort} / ${settings.logging.syslogFacility} / ${settings.logging.syslogLevel}</dd>
              </dl>
            </article>
            <article class="domain-card">
              <header><div><h3>Auxiliary services</h3><p>Credentials and filesystem paths stay redacted</p></div></header>
              <dl>
                <dt>CLI port / password</dt><dd>${settings.auxiliary.cliPort} / ${settings.auxiliary.cliPasswordConfigured ? 'Configured' : 'Not configured'}</dd>
                <dt>SOCKS async DNS</dt><dd>${settings.auxiliary.socksAsyncDns ? 'Enabled' : 'Disabled'}</dd>
                <dt>UDP quick ports</dt><dd>${settings.auxiliary.udpQuickPorts.join(', ') || 'None'}</dd>
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
                <dt>Listener</dt><dd>${settings.acceptApi ? 'Enabled' : 'Disabled'}</dd>
                <dt>API keys</dt><dd>${settings.httpApi.keyCount} configured</dd>
                <dt>Allowed IPs</dt><dd>${settings.httpApi.allowedIps.join(', ') || 'None'}</dd>
                <dt>Loopback only</dt><dd>${settings.httpApi.loopbackOnly ? 'Yes' : 'No'}</dd>
                <dt>API header access</dt><dd>${settings.httpApi.allowApiHeader ? 'Allowed' : 'Blocked'}</dd>
                <dt>PAM login</dt><dd>${settings.httpApi.pamLogin ? 'Enabled' : 'Disabled'}</dd>
              </dl>
            </article>
            <article class="domain-card">
              <header><div><h3>Webhook posture</h3><p>URLs and identities are redacted</p></div></header>
              <dl>
                <dt>Webhook</dt><dd>${settings.webhook.enabled ? 'Enabled' : 'Disabled'}</dd>
                <dt>URL</dt><dd>${settings.webhook.urlConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>TLS verification</dt><dd>${settings.webhook.tlsVerify ? 'Required' : 'Disabled'}</dd>
                <dt>Sift</dt><dd>${settings.webhook.siftEnabled ? 'Enabled' : 'Disabled'}</dd>
                <dt>API override</dt><dd>${settings.webhook.apiOverride ? 'Allowed' : 'Blocked'}</dd>
                <dt>Nameservers</dt><dd>${settings.nameservers.join(', ') || 'None'}</dd>
              </dl>
            </article>
          ` : nothing}
          ${debug ? html`
            <article class="domain-card">
              <header><div><h3>Debug logging</h3><p>Potentially expensive diagnostic controls</p></div>
                <button class="secondary" type="button" @click=${(event: Event) => this.openSystemDrawer('settings', event.currentTarget as HTMLElement)}>Edit</button>
              </header>
              <dl>
                <dt>Payload CRC</dt><dd>${debug.logDataCrc ? 'Enabled' : 'Disabled'}</dd>
                <dt>Socket events</dt><dd>${debug.logSockets ? 'Enabled' : 'Disabled'}</dd>
                <dt>Resolve online names</dt><dd>${debug.logOnlineConnectionName ? 'Enabled · expensive' : 'Disabled'}</dd>
                <dt>Source lines</dt><dd>${debug.logSourceLinesAlways ? 'Always' : debug.logSourceLines ? 'Diagnostic levels' : 'Disabled'}</dd>
                <dt>Module overrides</dt><dd>${debug.moduleOverrideCount} configured</dd>
              </dl>
            </article>
          ` : nothing}
          ${captures ? html`
            <article class="domain-card">
              <header><div><h3>Capture posture</h3><p>Paths and destinations are redacted</p></div>
                <button class="secondary" type="button" @click=${(event: Event) => this.openSystemDrawer('captures', event.currentTarget as HTMLElement)}>Edit</button>
              </header>
              <dl>
                <dt>Local capture</dt><dd>${captures.local.enabled ? 'Enabled' : 'Disabled'}</dd>
                <dt>Local target</dt><dd>${captures.local.directoryConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>Filename prefix / suffix</dt><dd>${captures.local.filePrefixConfigured ? 'Configured' : 'Empty'} / ${captures.local.fileSuffixConfigured ? 'Configured' : 'Empty'}</dd>
                <dt>Format / quota</dt><dd>${captures.local.format} / ${captures.local.quotaMiB} MiB</dd>
                <dt>Remote capture</dt><dd>${captures.remote.enabled ? 'Enabled' : 'Disabled'}</dd>
                <dt>Tunnel format</dt><dd>${captures.remote.tunnelType} / ${captures.remote.greFormat}</dd>
                <dt>Remote target</dt><dd>${captures.remote.destinationConfigured ? 'Configured · redacted' : 'Not configured'}</dd>
                <dt>TTL / bound interface</dt><dd>${captures.remote.ttl} / ${captures.remote.bindInterfaceConfigured ? 'Yes' : 'No'}</dd>
                <dt>Checksums</dt><dd>${captures.calculateChecksums ? 'Calculated' : 'Preserved'}</dd>
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
                      <span><strong>${authority.name}</strong> · ${authority.pathConfigured ? 'path configured' : 'path missing'}</span>
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
                        <span><strong>${signature.name}</strong> · ${signature.flow.length} flow step${signature.flow.length === 1 ? '' : 's'}</span>
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
    const events = [...this.operationalEvents.events].reverse();
    return html`
      <div class="content dashboard">
        <div class="section-head">
          <div>
            <h2>Operational events</h2>
            <p>Bounded, privacy-safe control-plane state transitions from the GUI core.</p>
          </div>
          <span class="runtime-state ${this.eventsError ? 'danger' : 'success'}">
            ${this.eventsError ? 'Unavailable' : `${events.length} transitions`}
          </span>
        </div>
        <div class="privacy-note">
          Smithproxy event-ring messages require a future authenticated Smithproxy HTTP API.
          This view intentionally does not parse the administrative CLI or expose arbitrary log text.
        </div>
        ${this.eventsError ? html`<div class="metrics-message">${this.eventsError}</div>` : nothing}
        ${events.length === 0 ? html`
          <div class="metrics-message">No control-plane state transition has been observed yet.</div>
        ` : html`
          <div class="event-list" role="list" aria-label="Operational events">
            ${events.map(event => html`
              <article class="event-row" role="listitem">
                <time class="event-time" datetime=${new Date(event.occurredAtUnixMs).toISOString()}>
                  ${new Date(event.occurredAtUnixMs).toLocaleString()}
                </time>
                <span class="event-severity ${event.severity}">${event.severity}</span>
                <strong>${event.message}</strong>
                <span class="event-source">${event.source}</span>
              </article>
            `)}
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

  private renderPolicyEditor(entry: DrawerEntry) {
    const policy = this.snapshot?.policies.find(item => item.id === entry.id);
    if (!policy) return nothing;
    const policyIndex = this.snapshot?.policies.findIndex(item => item.id === entry.id) ?? -1;
    const actionOrigin = this.snapshot?.valueOrigins.find(
      item => item.path === `policy.[${policyIndex}].action`,
    );
    const liveReadOnly = this.snapshot?.source === 'live' && !this.draftAvailable;
    const protocol = this.snapshot?.protocols.find(item => item.name === policy.protocol);
    return html`
      <div class="form-grid">
        <label for="policy-name-${entry.id}">Name</label>
        <input id="policy-name-${entry.id}" .value=${policy.name} .readOnly=${liveReadOnly} />
        <label>Enabled</label>
        <label><input id="policy-enabled-${entry.id}" type="checkbox"
          .checked=${policy.enabled} ?disabled=${liveReadOnly} /> Accept traffic for evaluation</label>
        <label for="policy-sources-${entry.id}">Sources</label>
        <div class="reference-stack">
          <input id="policy-sources-${entry.id}" .value=${policy.sources.map(item => item.name).join(', ')} .readOnly=${liveReadOnly} />
          ${policy.sources.map(reference => reference.id ? html`
          <button class="reference" type="button"
            @click=${(event: MouseEvent) => this.openAddress(reference.id!, event.currentTarget as HTMLElement)}>
            <span>${reference.name}</span><span aria-hidden="true">→</span>
          </button>
        ` : nothing)}</div>
        <label for="destination-${entry.id}">Destinations</label>
        <input id="destination-${entry.id}"
          .value=${policy.destinations.map(item => item.name).join(', ')} .readOnly=${liveReadOnly} />
        <label for="action-${entry.id}">Action</label>
        <input id="action-${entry.id}" .value=${String(actionOrigin?.persistentValue ?? policy.action)}
          .readOnly=${liveReadOnly || actionOrigin?.editable === false} />
      </div>
      <div class="section">
        <h3>Advanced</h3>
        <div class="form-grid">
          <label for="policy-protocol-${entry.id}">Protocol</label>
          <div class="reference-edit"><input id="policy-protocol-${entry.id}" .value=${policy.protocol} .readOnly=${liveReadOnly} />
            ${protocol ? html`<button class="reference" type="button"
              @click=${(event: MouseEvent) => this.openProtocol(protocol.id, event.currentTarget as HTMLElement)}>
              <span>${protocol.name}</span><span aria-hidden="true">→</span></button>` : nothing}</div>
          <label for="policy-source-ports-${entry.id}">Source ports</label>
          <div class="reference-stack"><input id="policy-source-ports-${entry.id}" .value=${policy.sourcePorts.join(', ')} .readOnly=${liveReadOnly} />${this.renderPortReferences(policy.sourcePorts)}</div>
          <label for="policy-destination-ports-${entry.id}">Destination ports</label>
          <div class="reference-stack"><input id="policy-destination-ports-${entry.id}" .value=${policy.destinationPorts.join(', ')} .readOnly=${liveReadOnly} />${this.renderPortReferences(policy.destinationPorts)}</div>
          ${this.renderPolicyProfileField(entry, 'tls', 'TLS profile', 'tls', policy.tlsProfile, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'routing', 'Routing profile', 'routing', policy.routing, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'detection', 'Detection profile', 'detection', policy.detectionProfile, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'content', 'Content profile', 'content', policy.contentProfile, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'ssh', 'SSH profile', 'ssh', policy.sshProfile, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'auth', 'Authentication profile', 'authentication', policy.authProfile, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'dns', 'DNS ALG profile', 'dns', policy.dnsProfile, liveReadOnly)}
          ${this.renderPolicyProfileField(entry, 'script', 'Script profile', 'script', policy.scriptProfile, liveReadOnly)}
          <label for="policy-features-${entry.id}">Features</label>
          <input id="policy-features-${entry.id}" .value=${policy.features.join(', ')} .readOnly=${liveReadOnly} />
          <label for="policy-nat-${entry.id}">NAT</label>
          <input id="policy-nat-${entry.id}" .value=${policy.nat} .readOnly=${liveReadOnly} />
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

  private renderPolicyProfileField(
    entry: DrawerEntry, id: string, label: string, type: string, value: string, readOnly: boolean,
  ) {
    return html`<label for="policy-${id}-${entry.id}">${label}</label>
      <div class="reference-edit"><input id="policy-${id}-${entry.id}" .value=${value} .readOnly=${readOnly} />
        ${this.renderProfileReference(type, value)}</div>`;
  }

  private renderAddressEditor(entry: DrawerEntry) {
    const address = this.snapshot?.addresses.find(item => item.id === entry.id);
    if (!address) return nothing;
    const readOnly = this.snapshot?.source === 'live' && !this.draftAvailable;
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
    const readOnly = this.snapshot?.source === 'live' && !this.draftAvailable;
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
    const readOnly = this.snapshot?.source === 'live' && !this.draftAvailable;
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
    return html`
      <div class=${tls || content || ssh ? 'form-grid wide-form-grid' : 'form-grid'}>
        <label for=${mapped ? `profile-name-${entry.id}` : nothing}>Name</label>
        ${mapped ? html`<input id="profile-name-${entry.id}"
          .value=${profile.name} .readOnly=${mappedReadOnly} />` : html`<span>${profile.name}</span>`}
        <label>Profile type</label><span class="action">${profile.type}</span>
        ${routing ? html`
          <label for="routing-addresses-${entry.id}">Destination addresses</label>
          <input id="routing-addresses-${entry.id}"
            .value=${routing.destinationAddresses.join(', ')} .readOnly=${mappedReadOnly} />
          <label>Address object links</label>
          <div class="reference-stack">${routing.destinationAddresses.length === 0 ? html`<span>None</span>` :
            routing.destinationAddresses.map(name => {
              const address = this.snapshot?.addresses.find(item => item.name === name);
              return address ? html`<button class="reference" type="button"
                @click=${(event: MouseEvent) => this.openAddress(address.id, event.currentTarget as HTMLElement)}>
                <span>${name}</span><span aria-hidden="true">→</span>
              </button>` : html`<span>${name}</span>`;
            })}</div>
          <label for="routing-ports-${entry.id}">Destination ports</label>
          <input id="routing-ports-${entry.id}"
            .value=${routing.destinationPorts.join(', ')} .readOnly=${mappedReadOnly} />
          <label>Port object links</label>
          ${this.renderPortReferences(routing.destinationPorts)}
          <label for="routing-load-balancing-${entry.id}">Load balancing</label>
          <select id="routing-load-balancing-${entry.id}"
            .value=${routing.loadBalancingMethod} ?disabled=${mappedReadOnly}>
            <option value="round-robin">Round robin</option>
            <option value="sticky-l3">Sticky L3</option>
            <option value="sticky-l4">Sticky L4</option>
          </select>
          <label for="routing-rewrite-sni-${entry.id}">Rewrite SNI match</label>
          <input id="routing-rewrite-sni-${entry.id}"
            .value=${routing.rewriteSni} .readOnly=${mappedReadOnly} placeholder="Disabled" />
          <label for="routing-rewrite-sni-to-${entry.id}">Rewrite SNI target</label>
          <input id="routing-rewrite-sni-to-${entry.id}"
            .value=${routing.rewriteSniTo} .readOnly=${mappedReadOnly} placeholder="Disabled" />
        ` : tls ? html`
          <label for="tls-inspect-${entry.id}">Inspection</label>
          ${this.renderBooleanSelect(`tls-inspect-${entry.id}`, tls.inspect, mappedReadOnly)}
          <label for="tls-allow-untrusted-${entry.id}">Allow untrusted issuers</label>
          ${this.renderBooleanSelect(`tls-allow-untrusted-${entry.id}`, tls.allowUntrustedIssuers, mappedReadOnly, 'Allowed', 'Rejected')}
          <label for="tls-allow-invalid-${entry.id}">Allow invalid certificates</label>
          ${this.renderBooleanSelect(`tls-allow-invalid-${entry.id}`, tls.allowInvalidCertificates, mappedReadOnly, 'Allowed', 'Rejected')}
          <label for="tls-allow-self-signed-${entry.id}">Allow self-signed certificates</label>
          ${this.renderBooleanSelect(`tls-allow-self-signed-${entry.id}`, tls.allowSelfSigned, mappedReadOnly, 'Allowed', 'Rejected')}
          <label for="tls-certificate-transparency-${entry.id}">Certificate transparency</label>
          ${this.renderBooleanSelect(`tls-certificate-transparency-${entry.id}`, tls.certificateTransparency, mappedReadOnly)}
          <label for="tls-ocsp-stapling-${entry.id}">OCSP stapling</label>
          ${this.renderBooleanSelect(`tls-ocsp-stapling-${entry.id}`, tls.ocspStapling, mappedReadOnly)}
          <label for="tls-block-alpn-${entry.id}">ALPN negotiation</label>
          ${this.renderBooleanSelect(`tls-block-alpn-${entry.id}`, tls.blockAlpn, mappedReadOnly, 'Blocked', 'Allowed')}
          <label for="tls-custom-only-${entry.id}">Custom certificates only</label>
          ${this.renderBooleanSelect(`tls-custom-only-${entry.id}`, tls.onlyCustomCertificates, mappedReadOnly, 'Required', 'Not required')}
          <label for="tls-no-fallback-${entry.id}">Fallback bypass</label>
          ${this.renderBooleanSelect(`tls-no-fallback-${entry.id}`, tls.noFallbackBypass, mappedReadOnly, 'Blocked', 'Allowed')}
          <label for="tls-key-log-${entry.id}">SSL key logging</label>
          ${this.renderBooleanSelect(`tls-key-log-${entry.id}`, tls.sslKeyLog, mappedReadOnly)}
          <label for="tls-hello-timeout-${entry.id}">Client hello timeout</label>
          <input id="tls-hello-timeout-${entry.id}" type="number" min="1" max="3600000"
            .value=${String(tls.clientHelloTimeoutMs)} .readOnly=${mappedReadOnly} />
          <label for="tls-handshake-timeout-${entry.id}">Handshake timeout</label>
          <input id="tls-handshake-timeout-${entry.id}" type="number" min="1" max="3600000"
            .value=${String(tls.handshakeTimeoutMs)} .readOnly=${mappedReadOnly} />
          <label for="tls-client-action-${entry.id}">Client certificate action</label>
          <select id="tls-client-action-${entry.id}" .value=${tls.clientCertificateAction} ?disabled=${mappedReadOnly}>
            <option value="block_or_replacement">Block or replacement</option>
            <option value="empty_client_cert">Empty client certificate</option>
            <option value="tls_bypass">TLS bypass</option>
            <option value="use_configured">Use configured certificate</option>
          </select>
          <label for="tls-alerts-${entry.id}">Alerts</label>
          <select id="tls-alerts-${entry.id}" .value=${tls.alerts} ?disabled=${mappedReadOnly}>
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
          <select id="detection-mode-${entry.id}" .value=${String(detection.mode)} ?disabled=${mappedReadOnly}>
            <option value="0">Disabled</option><option value="1">Pre-read</option><option value="2">Post-read</option>
          </select>
          <label for="detection-engines-${entry.id}">L7 engines</label>
          <select id="detection-engines-${entry.id}"
            .value=${String(detection.enginesEnabled)} ?disabled=${mappedReadOnly}>
            <option value="true">Enabled</option><option value="false">Disabled</option>
          </select>
          <label for="detection-kb-${entry.id}">Knowledge base</label>
          <select id="detection-kb-${entry.id}"
            .value=${String(detection.knowledgeBaseEnabled)} ?disabled=${mappedReadOnly}>
            <option value="true">Enabled</option><option value="false">Disabled</option>
          </select>
        ` : content ? html`
          <label for="content-write-payload-${entry.id}">Payload capture</label>
          ${this.renderBooleanSelect(`content-write-payload-${entry.id}`, content.writePayload, mappedReadOnly)}
          <label for="content-format-${entry.id}">Capture format</label>
          <select id="content-format-${entry.id}" .value=${content.writeFormat} ?disabled=${mappedReadOnly}>
            <option value="smcap">SMCAP</option><option value="pcap">PCAP</option>
            <option value="pcap_single">Single PCAP</option>
          </select>
          <label for="content-webhook-${entry.id}">Webhook</label>
          ${this.renderBooleanSelect(`content-webhook-${entry.id}`, content.webhookEnabled, mappedReadOnly)}
          <label for="content-webhook-lock-${entry.id}">Webhook traffic lock</label>
          ${this.renderBooleanSelect(`content-webhook-lock-${entry.id}`, content.webhookLocksTraffic, mappedReadOnly)}
          <label for="content-ja4-client-${entry.id}">JA4 TLS ClientHello</label>
          ${this.renderBooleanSelect(`content-ja4-client-${entry.id}`, content.ja4TlsClientHello, mappedReadOnly)}
          <label for="content-ja4-ignore-sni-${entry.id}">JA4 ignores SNI</label>
          ${this.renderBooleanSelect(`content-ja4-ignore-sni-${entry.id}`, content.ja4TlsClientHelloIgnoresSni, mappedReadOnly, 'Yes', 'No')}
          <label for="content-ja4-server-${entry.id}">JA4 TLS ServerHello</label>
          ${this.renderBooleanSelect(`content-ja4-server-${entry.id}`, content.ja4TlsServerHello, mappedReadOnly)}
          <label for="content-ja4-http-${entry.id}">JA4 HTTP</label>
          ${this.renderBooleanSelect(`content-ja4-http-${entry.id}`, content.ja4Http, mappedReadOnly)}
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
          <label>Content rules</label><span>${content.ruleCount} redacted rules · unchanged</span>
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
          <select id="ssh-host-key-policy-${entry.id}" .value=${ssh.hostKeyPolicy} ?disabled=${mappedReadOnly}>
            <option value="insecure">Insecure</option><option value="accept-new">Accept new</option>
            <option value="strict">Strict</option>
          </select>
          <label for="ssh-shell-${entry.id}">Shell</label>
          ${this.renderPassRejectSelect(`ssh-shell-${entry.id}`, ssh.shell, mappedReadOnly)}
          <label for="ssh-exec-${entry.id}">Exec</label>
          ${this.renderPassRejectSelect(`ssh-exec-${entry.id}`, ssh.exec, mappedReadOnly)}
          <label for="ssh-subsystem-${entry.id}">Subsystem</label>
          ${this.renderPassRejectSelect(`ssh-subsystem-${entry.id}`, ssh.subsystem, mappedReadOnly)}
          <label for="ssh-pty-${entry.id}">PTY</label>
          ${this.renderPassRejectSelect(`ssh-pty-${entry.id}`, ssh.pty, mappedReadOnly)}
          <label for="ssh-environment-${entry.id}">Environment</label>
          ${this.renderPassRejectSelect(`ssh-environment-${entry.id}`, ssh.environment, mappedReadOnly)}
          <label for="ssh-local-forward-${entry.id}">Local forwarding</label>
          ${this.renderPassRejectSelect(`ssh-local-forward-${entry.id}`, ssh.localForward, mappedReadOnly)}
          <label for="ssh-remote-forward-${entry.id}">Remote forwarding</label>
          ${this.renderPassRejectSelect(`ssh-remote-forward-${entry.id}`, ssh.remoteForward, mappedReadOnly)}
          <label for="ssh-x11-${entry.id}">X11 forwarding</label>
          ${this.renderPassRejectSelect(`ssh-x11-${entry.id}`, ssh.x11, mappedReadOnly)}
          <label for="ssh-agent-${entry.id}">Agent forwarding</label>
          ${this.renderPassRejectSelect(`ssh-agent-${entry.id}`, ssh.agent, mappedReadOnly)}
        ` : dns ? html`
          <label for="dns-match-${entry.id}">Match request ID</label>
          <select id="dns-match-${entry.id}" .value=${String(dns.matchRequestId)} ?disabled=${mappedReadOnly}>
            <option value="true">Enabled</option><option value="false">Disabled</option>
          </select>
          <label for="dns-randomize-${entry.id}">Randomize upstream ID</label>
          <select id="dns-randomize-${entry.id}" .value=${String(dns.randomizeId)} ?disabled=${mappedReadOnly}>
            <option value="true">Enabled</option><option value="false">Disabled</option>
          </select>
          <label for="dns-cached-${entry.id}">Cached responses</label>
          <select id="dns-cached-${entry.id}" .value=${String(dns.cachedResponses)} ?disabled=${mappedReadOnly}>
            <option value="true">Enabled</option><option value="false">Disabled</option>
          </select>
        ` : script ? html`
          <label for="script-runtime-${entry.id}">Runtime</label>
          <select id="script-runtime-${entry.id}" .value=${script.runtime} ?disabled=${mappedReadOnly}>
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
          ${this.renderBooleanSelect(`auth-authenticate-${entry.id}`, authentication.authenticate, mappedReadOnly)}
          <label for="auth-resolve-${entry.id}">Resolve identities</label>
          ${this.renderBooleanSelect(`auth-resolve-${entry.id}`, authentication.resolve, mappedReadOnly)}
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
    const booleanField = (id: string, label: string, value: boolean) => html`
      <label for="settings-${id}">${label}</label>
      ${this.renderBooleanSelect(`settings-${id}`, value, disabled)}
    `;
    const workerField = (id: string, label: string, value: number) => html`
      <label for="settings-worker-${id}">${label}</label>
      <input id="settings-worker-${id}" type="number" min="-1" max="4096"
        .value=${String(value)} .readOnly=${disabled} />
    `;
    const numericField = (id: string, label: string, value: number, maximum: number) => html`
      <label for="settings-${id}">${label}</label>
      <input id="settings-${id}" type="number" min="0" max=${String(maximum)}
        .value=${String(value)} .readOnly=${disabled} />
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
        ${numericField('port-quic', 'QUIC port', settings.ports.quic, 65535)}
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
        <select id="settings-logging-syslog-family" .value=${String(settings.logging.syslogFamily)} ?disabled=${disabled}>
          <option value="4">IPv4</option><option value="6">IPv6</option>
        </select>
        ${writeOnlyField('payload-directory', 'Payload directory', settings.logging.payloadDirectoryConfigured)}
        ${writeOnlyField('log-file', 'Log file', settings.logging.fileConfigured)}
        ${writeOnlyField('tls-key-log-file', 'TLS key log file', settings.logging.sslKeyFileConfigured)}
        ${writeOnlyField('syslog-server', 'Syslog server', settings.logging.syslogServerConfigured)}
        <h3 class="form-span">Auxiliary services</h3>
        ${numericField('aux-cli-port', 'CLI port', settings.auxiliary.cliPort, 65535)}
        ${booleanField('aux-socks-async-dns', 'SOCKS asynchronous DNS', settings.auxiliary.socksAsyncDns)}
        ${writeOnlyField('cli-password', 'CLI password', settings.auxiliary.cliPasswordConfigured, true)}
        <label for="settings-udp-quick-ports">UDP quick ports</label>
        <input id="settings-udp-quick-ports" .value=${settings.auxiliary.udpQuickPorts.join(', ')}
          placeholder="0, 53, 443" .readOnly=${disabled} />
        ${writeOnlyField('certificates-path', 'Certificates path', settings.auxiliary.certificatesPathConfigured)}
        ${writeOnlyField('certificate-password', 'Certificate password', settings.auxiliary.certificatePasswordConfigured, true)}
        ${writeOnlyField('ca-bundle-path', 'CA bundle path', settings.auxiliary.caBundlePathConfigured)}
        ${writeOnlyField('messages-directory', 'Message assets', settings.auxiliary.messagesDirectoryConfigured)}
        ${writeOnlyField('payload-prefix', 'Payload filename prefix', settings.auxiliary.payloadFilePrefixConfigured)}
        ${writeOnlyField('payload-suffix', 'Payload filename suffix', settings.auxiliary.payloadFileSuffixConfigured)}
        ${writeOnlyField('web-rating-key', 'Web rating key', settings.auxiliary.webRatingKeyConfigured, true)}
        ${booleanField('tls-autodetect', 'TLS autodetection', settings.tlsAutodetect)}
        ${booleanField('tls-autodetect-harder', 'Aggressive TLS autodetection', settings.tlsAutodetectHarder)}
        ${booleanField('kernel-tls', 'Kernel TLS', settings.kernelTls)}
        ${booleanField('api-loopback', 'API loopback only', settings.httpApi.loopbackOnly)}
        ${booleanField('api-pam', 'API PAM login', settings.httpApi.pamLogin)}
        ${booleanField('api-header', 'API header access', settings.httpApi.allowApiHeader)}
        ${booleanField('webhook-enabled', 'Webhook', settings.webhook.enabled)}
        ${booleanField('webhook-tls', 'Webhook TLS verification', settings.webhook.tlsVerify)}
        ${booleanField('webhook-sift', 'Webhook Sift', settings.webhook.siftEnabled)}
        ${booleanField('webhook-override', 'Webhook API override', settings.webhook.apiOverride)}
        <label for="settings-nameservers">Nameservers</label>
        <input id="settings-nameservers" .value=${settings.nameservers.join(', ')}
          placeholder="192.0.2.53, resolver.example" .readOnly=${disabled} />
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
        <input id="settings-api-allowed-ips" .value=${settings.httpApi.allowedIps.join(', ')}
          placeholder="127.0.0.1, 192.0.2.0/24" .readOnly=${disabled} />
        ${writeOnlyField('webhook-url', 'Webhook URL', settings.webhook.urlConfigured)}
        ${this.snapshot?.debug ? html`
          <h3 class="form-span">Debug logging</h3>
          <label for="debug-data-crc">Payload CRC logging</label>
          ${this.renderBooleanSelect('debug-data-crc', this.snapshot.debug.logDataCrc, disabled)}
          <label for="debug-sockets">Socket event logging</label>
          ${this.renderBooleanSelect('debug-sockets', this.snapshot.debug.logSockets, disabled)}
          <label for="debug-online-name">Resolve online connection names</label>
          ${this.renderBooleanSelect('debug-online-name', this.snapshot.debug.logOnlineConnectionName, disabled)}
          <label for="debug-source-lines">Source lines at diagnostic levels</label>
          ${this.renderBooleanSelect('debug-source-lines', this.snapshot.debug.logSourceLines, disabled)}
          <label for="debug-source-lines-always">Source lines at every level</label>
          ${this.renderBooleanSelect('debug-source-lines-always', this.snapshot.debug.logSourceLinesAlways, disabled)}
          <h3 class="form-span">Per-module overrides</h3>
          ${this.snapshot.debug.moduleOverrides.map((override, index) => {
            const id = `debug-module-${index}`;
            const label = `${override.name} module override`;
            return html`
              <label for=${id}>${label}</label>
              ${override.kind === 'boolean'
                ? this.renderBooleanSelect(id, Boolean(override.value), disabled)
                : html`<input id=${id} type=${override.kind === 'integer' ? 'number' : 'text'}
                    min=${override.kind === 'integer' ? '-2147483648' : nothing}
                    max=${override.kind === 'integer' ? '2147483647' : nothing}
                    maxlength=${override.kind === 'string' ? '32' : nothing}
                    .value=${String(override.value)} .readOnly=${disabled} />`}
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
        ${this.renderBooleanSelect('captures-local-enabled', captures.local.enabled, disabled)}
        <label for="captures-local-format">Local format</label>
        <select id="captures-local-format" .value=${captures.local.format} ?disabled=${disabled}>
          <option value="pcap_single">PCAP single</option><option value="pcap">PCAP</option><option value="smcap">SMCAP</option>
        </select>
        <label for="captures-local-quota">Local quota (MiB)</label>
        <input id="captures-local-quota" type="number" min="0" max="1048576"
          .value=${String(captures.local.quotaMiB)} .readOnly=${disabled} />
        ${writeOnlyField('local-directory', 'Local directory', captures.local.directoryConfigured)}
        ${writeOnlyField('local-prefix', 'Local filename prefix', captures.local.filePrefixConfigured)}
        ${writeOnlyField('local-suffix', 'Local filename suffix', captures.local.fileSuffixConfigured)}
        <label for="captures-remote-enabled">Remote capture</label>
        ${this.renderBooleanSelect('captures-remote-enabled', captures.remote.enabled, disabled)}
        <label>Tunnel type</label><span>${captures.remote.tunnelType.toUpperCase()} · unchanged</span>
        <label for="captures-gre-format">GRE format</label>
        <select id="captures-gre-format" .value=${captures.remote.greFormat} ?disabled=${disabled}>
          <option value="traffic">Traffic</option><option value="pcapng">PCAPNG</option>
        </select>
        <label for="captures-remote-ttl">Tunnel TTL</label>
        <input id="captures-remote-ttl" type="number" min="0" max="255"
          .value=${String(captures.remote.ttl)} .readOnly=${disabled} />
        ${writeOnlyField('remote-destination', 'Remote destination', captures.remote.destinationConfigured)}
        ${writeOnlyField('bind-interface', 'Bound interface', captures.remote.bindInterfaceConfigured)}
        <label for="captures-checksums">Calculate checksums</label>
        ${this.renderBooleanSelect('captures-checksums', captures.calculateChecksums, disabled)}
      </div>
    `;
  }

  private renderCertificateAuthorityEditor(entry: DrawerEntry) {
    const authority = this.snapshot?.securityAssets?.certificateAuthorities.find(item => item.id === entry.id);
    if (!authority) return nothing;
    const disabled = this.snapshot?.source === 'live' && !this.draftAvailable;
    return html`
      <div class="form-grid">
        <label for="authority-name-${entry.id}">Name</label>
        <input id="authority-name-${entry.id}" .value=${authority.name} .readOnly=${disabled} />
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

  private renderSignatureEditor(entry: DrawerEntry) {
    const signature = this.snapshot?.securityAssets?.signatures.find(item => item.id === entry.id);
    if (!signature) return nothing;
    const disabled = this.snapshot?.source === 'live' && !this.draftAvailable;
    return html`
      <div class="form-grid wide-form-grid">
        <label for="signature-category-${entry.id}">Category</label>
        <input id="signature-category-${entry.id}" maxlength="128" .value=${signature.category}
          .readOnly=${disabled} />
        <label for="signature-name-${entry.id}">Name</label>
        <input id="signature-name-${entry.id}" maxlength="128" .value=${signature.name}
          .readOnly=${disabled} />
        <label for="signature-side-${entry.id}">Connection side</label>
        <select id="signature-side-${entry.id}" .value=${signature.side} ?disabled=${disabled}>
          <option value="client">Client</option>
          <option value="server">Server</option>
        </select>
        <label for="signature-group-${entry.id}">Group</label>
        <input id="signature-group-${entry.id}" maxlength="128" .value=${signature.group}
          .readOnly=${disabled} />
        <label for="signature-enables-${entry.id}">Enables</label>
        <input id="signature-enables-${entry.id}" maxlength="128" .value=${signature.enables}
          .readOnly=${disabled} />
        <label for="signature-engine-${entry.id}">Engine</label>
        <input id="signature-engine-${entry.id}" maxlength="128" .value=${signature.engine}
          .readOnly=${disabled} />
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
    return html`
      <div class="form-grid wide-form-grid">
        <label>Signature</label><span>${signature.name}</span>
        <label for="signature-flow-side-${entry.id}">Direction</label>
        <select id="signature-flow-side-${entry.id}" .value=${step.side} ?disabled=${disabled}>
          <option value="r">Read</option>
          <option value="w">Write</option>
        </select>
        <label for="signature-flow-type-${entry.id}">Matcher</label>
        <select id="signature-flow-type-${entry.id}" .value=${step.type} ?disabled=${disabled}>
          <option value="regex">Regular expression</option>
          <option value="simple">Simple bytes</option>
        </select>
        <label for="signature-flow-start-${entry.id}">Byte offset</label>
        <input id="signature-flow-start-${entry.id}" type="number" min="0"
          .value=${String(step.bytesStart)} .readOnly=${disabled} />
        <label for="signature-flow-maximum-${entry.id}">Byte window</label>
        <input id="signature-flow-maximum-${entry.id}" type="number" min="0"
          .value=${String(step.bytesMax)} .readOnly=${disabled} />
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

  private renderAugmentOrigins(entry: DrawerEntry) {
    const prefix = this.originPrefix(entry);
    const origins = prefix ? this.snapshot?.valueOrigins.filter(item => item.path.startsWith(prefix)) ?? [] : [];
    if (origins.length === 0) return nothing;
    return html`
      <section class="section" aria-label="Effective value overlays">
        <h3>Effective value overlays</h3>
        ${origins.map(origin => html`
          <div class="origin-note">
            <strong>${origin.path.slice(prefix!.length)}</strong><br />
            Persistent <strong>${String(origin.persistentValue)}</strong>
            → ${origin.layers.map(layer => layer.priority === null
              ? layer.id
              : `${layer.id} (priority ${layer.priority})`).join(' → ')}
            → effective <strong>${String(origin.effectiveValue)}</strong>.
            ${origin.editable ? 'The persistent value is editable.' : 'The active layer owns this value.'}
          </div>
        `)}
      </section>`;
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
    if (entry.kind === 'settings') return this.renderSystemSettingsEditor();
    if (entry.kind === 'captures') return this.renderCaptureSettingsEditor();
    if (entry.kind === 'authority') return this.renderCertificateAuthorityEditor(entry);
    if (entry.kind === 'signature') return this.renderSignatureEditor(entry);
    if (entry.kind === 'signature-flow') return this.renderSignatureFlowEditor(entry);
    return this.renderProfileEditor(entry);
  }

  private renderDrawer(entry: DrawerEntry, index: number) {
    const saved = this.draftObjects.has(`${entry.kind}:${entry.id}`);
    const editLabel = `Edit ${entry.title}`;
    const closeLabel = `Close ${entry.title}`;
    const visibleDepth = Math.min(index, 5);
    const active = index === this.drawers.length - 1;
    const draftableKinds: ReadonlyArray<DrawerEntry['kind']> = [
      'policy', 'address', 'port', 'protocol', 'settings', 'captures', 'authority',
      'signature', 'signature-flow',
    ];
    const profile = entry.kind === 'profile'
      ? this.snapshot?.profiles.find(item => item.id === entry.id)
      : undefined;
    const mappedProfile = Boolean(
      profile?.routing || profile?.tls || profile?.detection || profile?.content || profile?.ssh || profile?.dns ||
      profile?.script || profile?.authentication,
    );
    const draftable = this.snapshot?.source !== 'live' ||
      (this.draftAvailable && (draftableKinds.includes(entry.kind) || mappedProfile));
    const readOnly = !draftable;
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
          ${this.renderAugmentOrigins(entry)}
        </div>
        <footer class="drawer-foot">
          <span class="validation">${this.draftError ?? (readOnly ? 'Read-only runtime view' : saved ? 'Saved to draft' : 'Validation ready')}</span>
          <button class="secondary" type="button" @click=${() => this.closeDrawer(index)}>Cancel</button>
          <button class="primary" type="button" ?disabled=${readOnly || this.draftSaving}
            @click=${() => this.saveToDraft(entry)}>${this.draftSaving ? 'Saving…' : 'Save to draft'}</button>
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
            ${this.snapshot?.source === 'live' && this.draftChangeCount > 0 ? html`
              <button class="secondary" type="button"
                ?disabled=${this.drawers.length > 0}
                @click=${() => {
                  this.discardDraftArmed = false;
                  this.activeSection = 'Draft';
                }}>Review draft · ${this.draftChangeCount}</button>
            ` : nothing}
            <input class="search" type="search" aria-label="Search" maxlength="128"
              placeholder="Search policies and objects" .value=${this.searchQuery}
              @input=${(event: InputEvent) => this.updateSearch((event.currentTarget as HTMLInputElement).value)} />
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
          <span class=${this.draftChangeCount ? 'draft' : ''}>Draft: ${this.draftChangeCount} changes</span>
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
