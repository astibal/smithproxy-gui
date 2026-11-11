import {LitElement, css, html, nothing, unsafeCSS} from 'lit';
import {customElement, property, query, state} from 'lit/decorators.js';
import type {FitAddon} from '@xterm/addon-fit';
import type {Terminal} from '@xterm/xterm';
import xtermStyles from '@xterm/xterm/css/xterm.css?inline';

type ConsoleState = 'idle' | 'connecting' | 'connected' | 'closed' | 'error';

@customElement('smithproxy-console')
export class SmithproxyConsole extends LitElement {
  @property({type: Boolean}) expanded = false;
  @property({type: Boolean, reflect: true}) contextual = false;
  @property({attribute: 'base-path'}) basePath = '/';
  @property({attribute: false}) commands: ReadonlyArray<string> = [];
  @state() private connectionState: ConsoleState = 'idle';
  @state() private connectionDetail = 'Open the console to connect to Smithproxy CLI.';
  @query('.terminal-host') private terminalHost?: HTMLElement;

  private terminal: Terminal | undefined;
  private fitAddon: FitAddon | undefined;
  private socket: WebSocket | undefined;
  private resizeObserver: ResizeObserver | undefined;
  private terminalLoading: Promise<void> | undefined;
  private pendingInput: string | undefined;
  private loadedCommandPath = '';

  /**
   * Open the shared console and navigate through trusted CLI commands supplied
   * by the GUI. Commands are queued until the broker connection is ready.
   */
  openAt(commands: ReadonlyArray<string>): void {
    if (commands.length === 0 || commands.some(command =>
      command.length === 0 || command.length > 256 || !/^[A-Za-z0-9_.\[\] -]+$/u.test(command))) return;

    // A contextual jump must not inherit an arbitrary config-tree location
    // left behind by earlier interactive work. Smithproxy's `end` command
    // walks back only one level, so a fresh broker session is the only
    // deterministic way to start the generated path at the CLI root.
    this.resetBrokerSession();
    this.pendingInput = `${commands.join('\r')}\r`;
    if (this.expanded) void this.openConsole();
  }

  static styles = [unsafeCSS(xtermStyles), css`
    :host { position: fixed; z-index: 18; right: 0; bottom: 30px; left: 216px; height: 32px;
      border-top: 1px solid var(--app-border, #2c4855); background: #081218;
      box-shadow: 0 -10px 30px #0000; color: var(--app-text, #e8eff1);
      transition: height 160ms ease, box-shadow 160ms ease; }
    :host([expanded]) { height: min(46dvh, 430px); box-shadow: 0 -12px 32px #0009; }
    :host([contextual]) { position: relative; z-index: auto; inset: auto; display: block;
      height: min(38dvh, 340px); border-bottom: 1px solid var(--app-border, #2c4855);
      box-shadow: inset 0 -10px 24px #0005; transition: none; }
    :host([contextual]) .console { grid-template-rows: 31px minmax(0, 1fr); }
    .console { display: grid; grid-template-rows: 31px minmax(0, 1fr); height: 100%; overflow: hidden; }
    header { display: flex; min-width: 0; gap: 8px; align-items: center; padding: 0 10px;
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
    .action { padding: 2px 7px; border: 1px solid var(--app-border, #2c4855); border-radius: 2px;
      background: transparent; color: var(--app-muted, #a6bac3); cursor: pointer; }
    .action:hover { color: var(--app-text, #e8eff1); }
    .terminal-host { min-width: 0; min-height: 0; padding: 8px 10px; }
    .xterm { height: 100%; }
    @media (max-width: 900px) { :host { left: 76px; } }
    @media (max-width: 620px) { :host { bottom: 36px; left: 0; } }
    @media (prefers-reduced-motion: reduce) { :host { transition: none; } }
  `];

  protected updated(changes: Map<PropertyKey, unknown>): void {
    if (changes.has('contextual')) {
      if (this.contextual) window.removeEventListener('keydown', this.handleShortcut, true);
      else window.addEventListener('keydown', this.handleShortcut, true);
    }
    if (changes.has('expanded')) {
      this.toggleAttribute('expanded', this.expanded);
      if (this.expanded) void this.openConsole();
    }
    if (this.contextual && changes.has('commands')) {
      const commandPath = this.commands.join('\r');
      if (commandPath && commandPath !== this.loadedCommandPath) {
        this.loadedCommandPath = commandPath;
        this.openAt(this.commands);
      }
    }
  }

  connectedCallback(): void {
    super.connectedCallback();
    if (!this.contextual) window.addEventListener('keydown', this.handleShortcut, true);
  }

  disconnectedCallback(): void {
    window.removeEventListener('keydown', this.handleShortcut, true);
    this.disconnect('Console closed.');
    this.resizeObserver?.disconnect();
    this.resizeObserver = undefined;
    this.terminal?.dispose();
    this.terminal = undefined;
    this.fitAddon = undefined;
    super.disconnectedCallback();
  }

  /** Toggles the console globally without stealing Backquote from form fields. */
  private readonly handleShortcut = (event: KeyboardEvent): void => {
    if (event.code !== 'Backquote' || event.repeat ||
        event.altKey || event.ctrlKey || event.metaKey) return;

    const path = event.composedPath();
    const insideEditor = path.some(target => target instanceof HTMLElement &&
      (target.matches('input, textarea, select') || target.isContentEditable));
    // xterm handles its own hidden textarea below. Ordinary form editors keep
    // the character as text and never toggle the console.
    if (insideEditor) return;

    event.preventDefault();
    this.requestToggle();
  };

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
      // The xterm helper textarea consumes keyboard events. Intercept the
      // local drawer shortcut at its capture boundary before xterm can turn
      // it into remote CLI input.
      this.terminalHost.addEventListener('keydown', event => {
        if (event.code !== 'Backquote' ||
            event.altKey || event.ctrlKey || event.metaKey) return;
        event.preventDefault();
        event.stopImmediatePropagation();
        this.requestToggle();
      }, true);
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

  /** Close the current CLI context without presenting it as an operator disconnect. */
  private resetBrokerSession(): void {
    const socket = this.socket;
    this.socket = undefined;
    socket?.close(1000, 'Opening configuration context');
    this.connectionState = 'connecting';
    this.connectionDetail = 'Opening configuration context…';
  }

  private requestToggle(): void {
    this.dispatchEvent(new CustomEvent('console-toggle', {
      bubbles: true, composed: true, detail: {expanded: !this.expanded},
    }));
  }

  protected render() {
    return html`
      <section class="console" aria-label=${this.contextual ? 'Object CLI console' : 'Smithproxy CLI console'}>
        <header>
          <button class="toggle" type="button" aria-expanded=${this.expanded}
            title="Toggle console (backquote / tilde)"
            @click=${() => this.requestToggle()}>
            <span class="prompt" aria-hidden="true">&gt;_</span><strong>${this.contextual ? 'Object CLI' : 'Console'}</strong>
            <span class="state ${this.connectionState}" title=${this.connectionDetail}>${this.connectionDetail}</span>
          </button>
          ${this.expanded && (this.connectionState === 'closed' || this.connectionState === 'error') ? html`
            <button class="action" type="button" @click=${() => this.connect()}>Reconnect</button>` : nothing}
          ${this.expanded && this.connectionState === 'connected' ? html`
            <button class="action" type="button"
              @click=${() => this.disconnect('CLI session closed.')}>Disconnect</button>` : nothing}
          <button class="action" type="button" aria-label=${this.contextual ? 'Close object CLI'
            : this.expanded ? 'Collapse console' : 'Expand console'}
            @click=${() => this.requestToggle()}>${this.expanded ? '⌄' : '⌃'}</button>
        </header>
        <div class="terminal-host" aria-label="Interactive Smithproxy terminal"></div>
      </section>`;
  }
}

declare global {
  interface HTMLElementTagNameMap {'smithproxy-console': SmithproxyConsole;}
}
