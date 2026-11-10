import {LitElement, css, html, nothing, unsafeCSS} from 'lit';
import {customElement, property, query, state} from 'lit/decorators.js';
import type {FitAddon} from '@xterm/addon-fit';
import type {Terminal} from '@xterm/xterm';
import xtermStyles from '@xterm/xterm/css/xterm.css?inline';

type ConsoleState = 'idle' | 'connecting' | 'connected' | 'closed' | 'error';

@customElement('smithproxy-console')
export class SmithproxyConsole extends LitElement {
  @property({type: Boolean}) expanded = false;
  @property({attribute: 'base-path'}) basePath = '/';
  @state() private connectionState: ConsoleState = 'idle';
  @state() private connectionDetail = 'Open the console to connect to Smithproxy CLI.';
  @query('.terminal-host') private terminalHost?: HTMLElement;

  private terminal: Terminal | undefined;
  private fitAddon: FitAddon | undefined;
  private socket: WebSocket | undefined;
  private resizeObserver: ResizeObserver | undefined;
  private terminalLoading: Promise<void> | undefined;
  private pendingInput: string | undefined;

  /**
   * Open the shared console and navigate through trusted CLI commands supplied
   * by the GUI. Commands are queued until the broker connection is ready.
   */
  openAt(commands: ReadonlyArray<string>): void {
    if (commands.length === 0 || commands.some(command =>
      command.length === 0 || command.length > 256 || !/^[A-Za-z0-9_.\[\] -]+$/u.test(command))) return;
    this.pendingInput = `${commands.join('\r')}\r`;
    this.flushPendingInput();
    if (this.expanded) void this.openConsole();
  }

  static styles = [unsafeCSS(xtermStyles), css`
    :host { position: fixed; z-index: 18; right: 0; bottom: 30px; left: 216px; height: 40px;
      border-top: 1px solid var(--app-border, #2c4855); background: #081218;
      box-shadow: 0 -10px 30px #0000; color: var(--app-text, #e8eff1);
      transition: height 160ms ease, box-shadow 160ms ease; }
    :host([expanded]) { height: min(46dvh, 430px); box-shadow: 0 -12px 32px #0009; }
    .console { display: grid; grid-template-rows: 39px minmax(0, 1fr); height: 100%; overflow: hidden; }
    header { display: flex; min-width: 0; gap: 10px; align-items: center; padding: 0 12px;
      background: var(--app-raised, #173440); }
    .toggle { display: flex; min-width: 0; flex: 1; gap: 9px; align-items: center; padding: 0;
      border: 0; background: transparent; color: inherit; cursor: pointer; text-align: left; }
    .prompt { color: var(--app-brand, #ff6b35); font: 700 13px ui-monospace, monospace; }
    strong { font-size: 13px; }
    .state { overflow: hidden; color: var(--app-muted, #a6bac3); font-size: 11px;
      text-overflow: ellipsis; white-space: nowrap; }
    .state.connected { color: var(--app-success, #4ade80); }
    .state.error { color: var(--app-danger, #fb7185); }
    .state.connecting { color: var(--app-warning, #facc15); }
    .action { padding: 4px 8px; border: 1px solid var(--app-border, #2c4855); border-radius: 2px;
      background: transparent; color: var(--app-muted, #a6bac3); cursor: pointer; }
    .action:hover { color: var(--app-text, #e8eff1); }
    .terminal-host { min-width: 0; min-height: 0; padding: 8px 10px; }
    .xterm { height: 100%; }
    @media (max-width: 900px) { :host { left: 76px; } }
    @media (max-width: 620px) { :host { bottom: 36px; left: 0; } }
    @media (prefers-reduced-motion: reduce) { :host { transition: none; } }
  `];

  protected updated(changes: Map<PropertyKey, unknown>): void {
    if (!changes.has('expanded')) return;
    this.toggleAttribute('expanded', this.expanded);
    if (this.expanded) void this.openConsole();
  }

  disconnectedCallback(): void {
    this.disconnect('Console closed.');
    this.resizeObserver?.disconnect();
    this.resizeObserver = undefined;
    this.terminal?.dispose();
    this.terminal = undefined;
    this.fitAddon = undefined;
    super.disconnectedCallback();
  }

  private async openConsole(): Promise<void> {
    await this.ensureTerminal();
    if (!this.expanded || !this.terminal) return;
    this.connect();
    requestAnimationFrame(() => { this.fitAddon?.fit(); this.terminal?.focus(); });
  }

  private async ensureTerminal(): Promise<void> {
    if (this.terminal || !this.terminalHost) return;
    if (this.terminalLoading) return this.terminalLoading;
    this.connectionState = 'connecting';
    this.connectionDetail = 'Loading terminal…';
    this.terminalLoading = (async () => {
      const [{Terminal}, {FitAddon}] = await Promise.all([
        import('@xterm/xterm'), import('@xterm/addon-fit'),
      ]);
      if (!this.terminalHost || !this.isConnected) return;
      this.fitAddon = new FitAddon();
      this.terminal = new Terminal({
        allowProposedApi: false, convertEol: false, cursorBlink: true, cursorStyle: 'block',
        fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace', fontSize: 13, scrollback: 4000,
        theme: {background: '#081218', foreground: '#dce8ec', cursor: '#ff7a45',
          selectionBackground: '#42677e99', black: '#0b151b', brightBlack: '#617680'},
      });
      this.terminal.loadAddon(this.fitAddon);
      this.terminal.open(this.terminalHost);
      this.terminal.onData(data => {
        if (this.socket?.readyState === WebSocket.OPEN) this.socket.send(data);
      });
      this.resizeObserver = new ResizeObserver(() => { if (this.expanded) this.fitAddon?.fit(); });
      this.resizeObserver.observe(this.terminalHost);
    })();
    try {
      await this.terminalLoading;
    } catch {
      this.connectionState = 'error';
      this.connectionDetail = 'Terminal renderer could not be loaded.';
    } finally {
      this.terminalLoading = undefined;
    }
  }

  private endpoint(): string {
    const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const path = this.basePath === '/' ? '/api/v1/console' : `${this.basePath}/api/v1/console`;
    return `${scheme}//${window.location.host}${path}`;
  }

  private connect(): void {
    if (!this.expanded || this.socket?.readyState === WebSocket.OPEN ||
        this.socket?.readyState === WebSocket.CONNECTING) return;
    this.connectionState = 'connecting';
    this.connectionDetail = 'Connecting to Smithproxy CLI…';
    const socket = new WebSocket(this.endpoint(), 'smithproxy-cli-v1');
    socket.binaryType = 'arraybuffer';
    this.socket = socket;
    socket.addEventListener('open', () => {
      if (this.socket !== socket) return;
      this.connectionState = 'connected';
      this.connectionDetail = 'Connected to Smithproxy CLI';
      this.flushPendingInput();
      this.terminal?.focus();
    });
    socket.addEventListener('message', event => {
      if (this.socket !== socket) return;
      if (typeof event.data === 'string') this.terminal?.write(event.data);
      else if (event.data instanceof ArrayBuffer) this.terminal?.write(new Uint8Array(event.data));
    });
    socket.addEventListener('error', () => {
      if (this.socket !== socket) return;
      this.connectionState = 'error';
      this.connectionDetail = 'Smithproxy CLI connection failed.';
    });
    socket.addEventListener('close', () => {
      if (this.socket !== socket) return;
      this.socket = undefined;
      if (this.connectionState !== 'error') {
        this.connectionState = 'closed';
        this.connectionDetail = 'CLI session closed. Reconnect when needed.';
      }
    });
  }

  private flushPendingInput(): void {
    if (!this.pendingInput || this.socket?.readyState !== WebSocket.OPEN) return;
    this.socket.send(this.pendingInput);
    this.pendingInput = undefined;
  }

  private disconnect(detail: string): void {
    const socket = this.socket;
    this.socket = undefined;
    socket?.close(1000, 'Console closed');
    this.connectionState = 'closed';
    this.connectionDetail = detail;
  }

  private requestToggle(): void {
    this.dispatchEvent(new CustomEvent('console-toggle', {
      bubbles: true, composed: true, detail: {expanded: !this.expanded},
    }));
  }

  protected render() {
    return html`
      <section class="console" aria-label="Smithproxy CLI console">
        <header>
          <button class="toggle" type="button" aria-expanded=${this.expanded}
            @click=${() => this.requestToggle()}>
            <span class="prompt" aria-hidden="true">&gt;_</span><strong>Console</strong>
            <span class="state ${this.connectionState}" title=${this.connectionDetail}>${this.connectionDetail}</span>
          </button>
          ${this.expanded && (this.connectionState === 'closed' || this.connectionState === 'error') ? html`
            <button class="action" type="button" @click=${() => this.connect()}>Reconnect</button>` : nothing}
          ${this.expanded && this.connectionState === 'connected' ? html`
            <button class="action" type="button"
              @click=${() => this.disconnect('CLI session closed.')}>Disconnect</button>` : nothing}
          <button class="action" type="button" aria-label=${this.expanded ? 'Collapse console' : 'Expand console'}
            @click=${() => this.requestToggle()}>${this.expanded ? '⌄' : '⌃'}</button>
        </header>
        <div class="terminal-host" aria-label="Interactive Smithproxy terminal"></div>
      </section>`;
  }
}

declare global {
  interface HTMLElementTagNameMap {'smithproxy-console': SmithproxyConsole;}
}
