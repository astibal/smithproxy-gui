import {LitElement, css, html, nothing} from 'lit';
import {customElement, property, state} from 'lit/decorators.js';
import {FakeConfigClient} from './api/fake-client';
import type {AddressObject, ConfigSnapshot, PolicySummary} from './api/models';
import {SystemClient} from './api/system-client';
import {readRuntimeConfig, type RuntimeConfig} from './config/runtime-config';
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

  private readonly client = new FakeConfigClient();
  private readonly drawerStore = new DrawerStore();
  private runtime?: RuntimeConfig;
  private systemClient?: SystemClient;
  private systemProbeTimer: number | undefined;
  private systemProbeInFlight = false;

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
    .brand-mark { display: grid; width: 30px; height: 30px; place-items: center; border-radius: 8px; background: var(--app-brand); color: var(--app-on-brand); }
    nav { display: grid; gap: 4px; }
    nav button { width: 100%; padding: 10px 12px; border: 0; border-radius: 7px; background: transparent; color: var(--app-muted); text-align: left; cursor: pointer; }
    nav button:hover { background: var(--app-raised); color: var(--app-text); }
    nav button[aria-current='page'] { background: var(--app-raised); color: var(--app-text); box-shadow: inset 3px 0 var(--app-brand); }

    .main { display: grid; grid-template-rows: 58px minmax(0, 1fr); min-width: 0; min-height: 0; }
    .topbar { display: flex; gap: 16px; align-items: center; padding: 0 20px; border-bottom: 1px solid var(--app-border); background: color-mix(in srgb, var(--app-surface) 88%, transparent); }
    .topbar h1 { margin: 0; font-size: 18px; }
    .topbar p { flex: 1; margin: 0; color: var(--app-muted); }
    .search { width: min(300px, 32vw); padding: 8px 10px; border: 1px solid var(--app-border); border-radius: 7px; background: var(--app-input); color: var(--app-text); }

    .workspace { position: relative; min-width: 0; min-height: 0; overflow: hidden; }
    .content { height: 100%; overflow: auto; padding: 22px; }
    .section-head { display: flex; align-items: end; justify-content: space-between; margin-bottom: 16px; }
    .section-head h2 { margin: 0 0 3px; font-size: 20px; }
    .section-head p { margin: 0; color: var(--app-muted); }
    .primary { padding: 8px 13px; border: 1px solid var(--app-brand); border-radius: 7px; background: var(--app-brand); color: var(--app-on-brand); font-weight: 650; cursor: pointer; }

    .dashboard { display: grid; gap: 18px; }
    .metric-grid { display: grid; grid-template-columns: repeat(4, minmax(150px, 1fr)); gap: 12px; }
    .metric, .monitor-panel { border: 1px solid var(--app-border); border-radius: 10px; background: var(--app-surface); }
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
    .probe { min-height: 12px; height: 100%; border-radius: 3px; background: var(--app-border); }
    .probe.ready { background: var(--app-success); }
    .probe.starting, .probe.unreachable, .probe.unconfigured { background: var(--app-warning); }
    .probe.unauthorized, .probe.error { background: var(--app-danger); }
    .scope-note { padding: 12px 14px; border-left: 3px solid var(--app-brand); background: var(--app-raised); color: var(--app-muted); }

    .table { overflow: hidden; border: 1px solid var(--app-border); border-radius: 10px; background: var(--app-surface); }
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
    .drawer-head { display: flex; gap: 12px; align-items: center; padding: 15px 18px; border-bottom: 1px solid var(--app-border); background: var(--app-raised); }
    .drawer-title { flex: 1; min-width: 0; }
    .drawer-title small { display: block; color: var(--app-muted); }
    .drawer-title h2 { overflow: hidden; margin: 1px 0 0; font-size: 18px; text-overflow: ellipsis; white-space: nowrap; }
    .icon-button { display: grid; width: 34px; height: 34px; place-items: center; border: 1px solid var(--app-border); border-radius: 7px; background: transparent; cursor: pointer; }
    .drawer-body { overflow: auto; padding: 22px 24px 32px; }
    .drawer-foot { display: flex; gap: 10px; align-items: center; padding: 12px 18px; border-top: 1px solid var(--app-border); background: var(--app-raised); }
    .drawer-foot .validation { flex: 1; color: var(--app-success); }
    .secondary { padding: 8px 13px; border: 1px solid var(--app-border-strong); border-radius: 7px; background: transparent; cursor: pointer; }
    .form-grid { display: grid; grid-template-columns: minmax(120px, 0.35fr) minmax(240px, 1fr); gap: 18px 24px; max-width: 920px; }
    .form-grid label { align-self: center; color: var(--app-muted); }
    .form-grid input, .form-grid select, .form-grid textarea { width: 100%; padding: 9px 10px; border: 1px solid var(--app-border); border-radius: 7px; background: var(--app-input); color: var(--app-text); }
    .reference { display: flex; align-items: center; justify-content: space-between; width: 100%; padding: 10px 12px; border: 1px solid var(--app-border); border-radius: 7px; background: var(--app-input); cursor: pointer; }
    .section { margin-top: 28px; padding-top: 20px; border-top: 1px solid var(--app-border); }
    .section h3 { margin: 0 0 12px; font-size: 15px; }
    .impact { padding: 12px 14px; border: 1px solid color-mix(in srgb, var(--app-warning) 48%, var(--app-border)); border-radius: 8px; background: var(--app-warning-bg); color: var(--app-warning); }
    .usage { margin: 12px 0 0; padding: 0; list-style: none; }
    .usage li { padding: 7px 0; border-bottom: 1px solid var(--app-border); }

    .statusbar { grid-column: 1 / -1; display: flex; gap: 20px; align-items: center; padding: 0 12px; border-top: 1px solid var(--app-border); background: var(--app-raised); color: var(--app-muted); font-size: 12px; }
    .system-state { color: var(--app-muted); }
    .system-state.success { color: var(--app-success); }
    .system-state.warning { color: var(--app-warning); }
    .system-state.danger { color: var(--app-danger); }
    .draft { color: var(--app-warning); }
    .spacer { flex: 1; }

    .error { margin: 24px; padding: 16px; border: 1px solid var(--app-danger); border-radius: 8px; color: var(--app-danger); }
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
      void this.loadCapabilities();
      void this.probeSystem();
    } catch (error) {
      this.systemStatus = statusFromFailure(error);
    }
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
    window.addEventListener('online', this.handleOnline);
    void this.load();
  }

  disconnectedCallback(): void {
    this.clearSystemProbe();
    document.removeEventListener('visibilitychange', this.handleVisibilityChange);
    window.removeEventListener('online', this.handleOnline);
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
    if (!this.systemClient || this.systemProbeInFlight || document.visibilityState === 'hidden') return;
    this.systemProbeInFlight = true;
    try {
      this.systemStatus = statusFromSnapshot(await this.systemClient.status());
      if (this.apiVersion === 'unavailable') void this.loadCapabilities();
    } catch (error) {
      this.systemStatus = statusFromFailure(error);
    } finally {
      this.systemProbeInFlight = false;
      this.scheduleSystemProbe();
    }
  }

  private async loadCapabilities(): Promise<void> {
    if (!this.systemClient) return;
    try {
      this.apiVersion = (await this.systemClient.capabilities()).apiVersion;
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

  private async load(): Promise<void> {
    try {
      this.snapshot = await this.client.loadSnapshot();
    } catch (error) {
      this.loadingError = error instanceof Error ? error.message : 'Unable to load configuration.';
    }
  }

  private openPolicy(policy: PolicySummary): void {
    this.drawerStore.open({kind: 'policy', id: policy.id, title: policy.name});
    this.syncDrawers();
  }

  private openAddress(id: string): void {
    const address = this.snapshot?.addresses.find(item => item.id === id);
    if (!address) return;
    this.drawerStore.open({kind: 'address', id: address.id, title: address.name});
    this.syncDrawers();
  }

  private closeDrawer(index: number): void {
    this.drawerStore.closeFrom(index);
    this.syncDrawers();
  }

  private syncDrawers(): void {
    this.drawers = [...this.drawerStore.entries];
  }

  private saveToDraft(entry: DrawerEntry): void {
    this.draftObjects = new Set(this.draftObjects).add(`${entry.kind}:${entry.id}`);
  }

  private handleKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape' && this.drawers.length > 0) {
      event.preventDefault();
      this.drawerStore.closeTop();
      this.syncDrawers();
    }
  }

  private renderPolicyList() {
    return html`
      <div class="content">
        <div class="section-head">
          <div><h2>Policies</h2><p>Traffic decisions and inspection behavior</p></div>
          <button class="primary" type="button">New policy</button>
        </div>
        <div class="table" role="group" aria-label="Policies">
          <div class="row heading" aria-hidden="true">
            <span>Name</span><span>Source</span><span>Destination</span><span>Action</span><span>Status</span>
          </div>
          ${this.snapshot?.policies.map(policy => html`
            <button class="row" type="button" @click=${() => this.openPolicy(policy)}>
              <strong>${policy.name}</strong>
              <span>${policy.sourceName}</span>
              <span>${policy.destinationName}</span>
              <span class="action">${policy.action}</span>
              <span class="status ${policy.enabled ? '' : 'disabled'}">${policy.enabled ? 'Enabled' : 'Disabled'}</span>
            </button>
          `)}
        </div>
      </div>
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
          This view measures the authenticated control-plane API ping only. It does not yet represent listener, traffic, TLS inspection, or dataplane health.
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
    return html`
      <div class="form-grid">
        <label for="policy-name-${entry.id}">Name</label>
        <input id="policy-name-${entry.id}" .value=${policy.name} />
        <label>Enabled</label>
        <label><input type="checkbox" .checked=${policy.enabled} /> Accept traffic for evaluation</label>
        <label>Source</label>
        <button class="reference" type="button" @click=${() => this.openAddress(policy.sourceId)}>
          <span>${policy.sourceName}</span><span aria-hidden="true">→</span>
        </button>
        <label for="destination-${entry.id}">Destination</label>
        <input id="destination-${entry.id}" .value=${policy.destinationName} />
        <label for="action-${entry.id}">Action</label>
        <select id="action-${entry.id}" .value=${policy.action}>
          <option value="inspect">Inspect</option><option value="bypass">Bypass</option><option value="block">Block</option>
        </select>
      </div>
      <div class="section"><h3>Advanced</h3><p>Protocol, TLS, content and logging controls will be generated from the configuration schema.</p></div>
    `;
  }

  private renderAddressEditor(entry: DrawerEntry) {
    const address = this.snapshot?.addresses.find(item => item.id === entry.id);
    if (!address) return nothing;
    return html`
      <div class="form-grid">
        <label for="address-name-${entry.id}">Name</label>
        <input id="address-name-${entry.id}" .value=${address.name} />
        <label for="address-type-${entry.id}">Type</label>
        <select id="address-type-${entry.id}" .value=${address.type}>
          <option value="host">Host</option><option value="subnet">Subnet</option><option value="range">Range</option>
        </select>
        <label for="address-value-${entry.id}">Address</label>
        <input id="address-value-${entry.id}" .value=${address.value} />
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

  private renderDrawer(entry: DrawerEntry, index: number) {
    const saved = this.draftObjects.has(`${entry.kind}:${entry.id}`);
    const editLabel = `Edit ${entry.title}`;
    const closeLabel = `Close ${entry.title}`;
    const visibleDepth = Math.min(index, 5);
    return html`
      <section class="drawer" data-depth=${visibleDepth} aria-label=${editLabel}>
        <header class="drawer-head">
          <div class="drawer-title"><small>Edit ${entry.kind}</small><h2>${entry.title}</h2></div>
          <button class="icon-button" type="button" aria-label=${closeLabel} @click=${() => this.closeDrawer(index)}>×</button>
        </header>
        <div class="drawer-body">
          ${entry.kind === 'policy' ? this.renderPolicyEditor(entry) : this.renderAddressEditor(entry)}
        </div>
        <footer class="drawer-foot">
          <span class="validation">${saved ? 'Saved to draft' : 'Validation ready'}</span>
          <button class="secondary" type="button" @click=${() => this.closeDrawer(index)}>Cancel</button>
          <button class="primary" type="button" @click=${() => this.saveToDraft(entry)}>Save to draft</button>
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
            ${this.renderContent()}
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
          <span>Config: demo</span><span>API: ${this.apiVersion}</span><span class="spacer"></span>
          <span>Revision ${this.snapshot?.revision ?? 'loading'}</span>
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
