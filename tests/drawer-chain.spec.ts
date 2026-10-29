import {expect, test, type Page} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const saslikVisualThemes = {
  'grill-dark': {
    canvas: '#0b0d0f', surface: '#121519', 'surface-raised': '#20242a', text: '#f2efe7',
    muted: '#a6a9ae', border: '#292e35', 'border-strong': '#6b818c', brand: '#ff6b35',
    'on-brand': '#140b07', input: '#0b0d0f', focus: '#a2c3ca', success: '#58d68d',
    'success-bg': '#142c20', warning: '#f5b942', 'warning-bg': '#342b1d', danger: '#ff7892',
    shadow: '#00000066',
  },
  'grill-light': {
    canvas: '#f2ece4', surface: '#fffaf3', 'surface-raised': '#e9dfd2', text: '#292018',
    muted: '#514338', border: '#c6b7a5', 'border-strong': '#688491', brand: '#ff6b35',
    'on-brand': '#140b07', input: '#fffaf3', focus: '#963b19', success: '#176448',
    'success-bg': '#e0f3e9', warning: '#795208', 'warning-bg': '#fff0c8', danger: '#ab253e',
    shadow: '#132f4926',
  },
  'petroleum-dark': {
    canvas: '#0c1923', surface: '#122b36', 'surface-raised': '#173440', text: '#e8eff1',
    muted: '#a6bac3', border: '#2c4855', 'border-strong': '#6b818c', brand: '#d99152',
    'on-brand': '#20160e', input: '#0c1923', focus: '#a2c3ca', success: '#58d68d',
    'success-bg': '#142c20', warning: '#f5b942', 'warning-bg': '#342b1d', danger: '#ff7892',
    shadow: '#00000066',
  },
  'petroleum-light': {
    canvas: '#dce9f2', surface: '#e8f1f6', 'surface-raised': '#cddfea', text: '#122530',
    muted: '#122530', border: '#b2c8d6', 'border-strong': '#688491', brand: '#d99152',
    'on-brand': '#20160e', input: '#e8f1f6', focus: '#27566d', success: '#176448',
    'success-bg': '#e0f3e9', warning: '#795208', 'warning-bg': '#fff0c8', danger: '#ab253e',
    shadow: '#132f4926',
  },
} as const;

type SaslikVisualTheme = keyof typeof saslikVisualThemes;

async function applySaslikVisualTheme(page: Page, theme: SaslikVisualTheme): Promise<void> {
  const [palette, mode] = theme.split('-') as ['grill' | 'petroleum', 'dark' | 'light'];
  await page.locator('html').evaluate((root, fixture) => {
    root.dataset.saslikApp = 'smithproxy-gui';
    root.dataset.saslikTheme = fixture.palette;
    root.dataset.saslikMode = fixture.mode;
    root.style.colorScheme = fixture.mode;
    for (const [name, value] of Object.entries(fixture.tokens)) {
      root.style.setProperty(`--st-${name}`, value);
    }
  }, {palette, mode, tokens: saslikVisualThemes[theme]});
}

type MockState = {
  smithproxy: 'ready' | 'unreachable';
  now?: number;
  configFetches?: number;
  conflictNextDraftWrite?: boolean;
  draftMutationVersions?: number[];
};

async function mockSystemApi(page: Page, state: MockState, configRead = false): Promise<void> {
  const now = (): number => state.now ?? Date.now();
  let draft = {id: 'workspace-draft', base_revision: null, version: 0, changes: [] as Array<{path: string; value: unknown}>};
  await page.route('**/api/v1/capabilities', async route => route.fulfill({json: {
    service: 'smithproxy-gui',
    api_version: 'v1',
    base_path: '/',
    smithproxy_state: state.smithproxy,
    features: {
      config_read: configRead, config_write: false, drafts: configRead, jobs: false, events: true, alerts: true,
      smithproxy_events: false,
      metrics: true, session_activity: true, tls_monitoring: true, neighbor_monitoring: true,
    },
  }}));
  await page.route('**/api/v1/status', async route => route.fulfill({json: {
    service: 'smithproxy-gui',
    uptime_ms: 65000,
    smithproxy: {
      configured: true,
      state: state.smithproxy,
      detail: state.smithproxy === 'ready' ? 'Connected' : 'Connection timed out',
      checked_at_unix_ms: now(),
      last_success_at_unix_ms: now() - 5000,
      latency_ms: state.smithproxy === 'ready' ? 12 : 2500,
      total_probes: 3,
      consecutive_failures: state.smithproxy === 'ready' ? 0 : 1,
      availability_window: {samples: 2, successful: state.smithproxy === 'ready' ? 2 : 1},
      history: state.smithproxy === 'ready'
        ? [
            {state: 'ready', checked_at_unix_ms: now() - 5000, latency_ms: 11},
            {state: 'ready', checked_at_unix_ms: now(), latency_ms: 12},
          ]
        : [
            {state: 'ready', checked_at_unix_ms: now() - 5000, latency_ms: 11},
            {state: 'unreachable', checked_at_unix_ms: now(), latency_ms: 2500},
          ],
    },
  }}));
  await page.route('**/api/v1/metrics/summary', async route => route.fulfill({json: {
    state: state.smithproxy === 'ready' ? 'ready' : 'unavailable',
    detail: state.smithproxy === 'ready' ? 'Current listener metrics' : 'Metrics are stale',
    checked_at_unix_ms: now(),
    last_success_at_unix_ms: now() - 5000,
    totals: {workers: 3, sessions_total: 19, sessions_active: 4, bytes_up: 1536, bytes_down: 2304},
    history: [
      {state: 'ready', checked_at_unix_ms: now() - 10000, sessions_active: 2,
       bytes_up: 1000, bytes_down: 1400},
      {state: 'ready', checked_at_unix_ms: now() - 5000, sessions_active: 3,
       bytes_up: 1200, bytes_down: 1800},
      {state: state.smithproxy === 'ready' ? 'ready' : 'unavailable', checked_at_unix_ms: now(),
       sessions_active: 4, bytes_up: 1536, bytes_down: 2304},
    ],
    listeners: [
      {name: 'tcp', workers: 2, sessions_total: 12, sessions_active: 3, bytes_up: 1024, bytes_down: 2048},
      {name: 'tls', workers: 1, sessions_total: 7, sessions_active: 1, bytes_up: 512, bytes_down: 256},
    ],
  }}));
  await page.route('**/api/v1/sessions/activity', async route => route.fulfill({json: {
    state: state.smithproxy === 'ready' ? 'ready' : 'unavailable',
    detail: state.smithproxy === 'ready' ? 'Current session activity' : 'Session activity is stale',
    checked_at_unix_ms: now(),
    last_success_at_unix_ms: now() - 5000,
    total: 4,
    speed_up: 1536,
    speed_down: 2304,
    protocols: [
      {protocol: 'tcp', sessions: 3, speed_up: 1024, speed_down: 2048, bytes_up: 4096, bytes_down: 8192},
      {protocol: 'tls', sessions: 1, speed_up: 512, speed_down: 256, bytes_up: 2048, bytes_down: 1024},
    ],
  }}));
  await page.route('**/api/v1/tls/cache/summary', async route => route.fulfill({json: {
    state: state.smithproxy === 'ready' ? 'ready' : 'unavailable',
    detail: state.smithproxy === 'ready' ? 'Current TLS cache metrics' : 'TLS cache metrics are stale',
    checked_at_unix_ms: now(), last_success_at_unix_ms: now() - 5000,
    size: 42, capacity: 1000,
  }}));
  await page.route('**/api/v1/network/neighbors/summary', async route => route.fulfill({json: {
    state: state.smithproxy === 'ready' ? 'ready' : 'unavailable',
    detail: state.smithproxy === 'ready' ? 'Current neighborhood aggregates' : 'Neighborhood is stale',
    checked_at_unix_ms: now(), last_success_at_unix_ms: now() - 5000,
    hosts_total: 8, active_today: 3, active_week: 6, tagged_hosts: 4,
    observations: 20, bytes_up: 1000, bytes_down: 2000,
  }}));
  await page.route('**/api/v1/events/recent', async route => route.fulfill({json: {
    source: 'gui-core', smithproxy_events_available: false,
    events: [
      {
        id: '0-100', source_revision: 1, occurred_at_unix_ms: now() - 5000, severity: 'info',
        source: 'gui-core', message: 'Smithproxy control plane is reachable',
      },
      ...(state.smithproxy === 'ready' ? [] : [{
        id: '1-200', source_revision: 2, occurred_at_unix_ms: now(), severity: 'error',
        source: 'gui-core', message: 'Smithproxy control plane changed to unreachable',
      }]),
    ],
  }}));
  await page.route('**/api/v1/events', async route => route.fulfill({
    contentType: 'text/event-stream; charset=utf-8',
    body: `retry: 60000\nevent: snapshot\ndata: ${JSON.stringify({
      source: 'gui-core', smithproxy_events_available: false,
      events: [{
        id: 'stream-100', source_revision: 1, occurred_at_unix_ms: now(), severity: 'info',
        source: 'gui-core', message: 'Smithproxy control plane is reachable',
      }],
    })}\n\n`,
  }));
  await page.route('**/api/v1/alerts', async route => route.fulfill({json: {
    source: 'gui-core', generated_at_unix_ms: now(),
    alerts: state.smithproxy === 'ready' ? [] : [{
      id: 'control-plane-unavailable', severity: 'critical', title: 'Control plane is unavailable',
      detail: 'The GUI core cannot currently reach the authenticated Smithproxy API.',
    }],
  }}));
  await page.route('**/api/v1/config/draft', async route => route.fulfill({json: draft}));
  await page.route('**/api/v1/config/draft/clear', async route => {
    const body = route.request().postDataJSON() as {expected_version: number};
    if (body.expected_version !== draft.version) {
      await route.fulfill({status: 409, json: {error: 'draft version conflict'}});
      return;
    }
    draft = {...draft, version: draft.version + 1, changes: []};
    await route.fulfill({json: draft});
  });
  await page.route('**/api/v1/config/draft/changes', async route => {
    const request = route.request();
    const body = request.postDataJSON() as {
      expected_version: number;
      changes: Array<{path: string; value: unknown}>;
    };
    state.draftMutationVersions?.push(body.expected_version);
    if (state.conflictNextDraftWrite) {
      state.conflictNextDraftWrite = false;
      draft = {
        ...draft,
        version: draft.version + 1,
        changes: [{path: 'settings.policy_fail_open', value: true}],
      };
      await route.fulfill({status: 409, json: {error: 'draft version conflict'}});
      return;
    }
    if (body.expected_version !== draft.version) {
      await route.fulfill({status: 409, json: {error: 'draft version conflict'}});
      return;
    }
    draft = {
      ...draft,
      version: draft.version + 1,
      changes: [
        ...draft.changes.filter(item => !body.changes.some(change => change.path === item.path)),
        ...body.changes,
      ],
    };
    await route.fulfill({json: draft});
  });
  if (configRead) {
    await page.route('**/api/v1/config/snapshot', async route => {
      state.configFetches = (state.configFetches ?? 0) + 1;
      await route.fulfill({json: {
      state: 'ready', detail: 'Current runtime configuration', checked_at_unix_ms: now(),
      last_success_at_unix_ms: now(), view: 'runtime', revision: null,
      policies: [{
        id: 'policy-0', name: 'Policy 1', enabled: true, protocol: 'tcp', sources: ['office'],
        source_ports: ['any'], destinations: ['internet'], destination_ports: ['https'],
        features: ['sinkhole'],
        action: 'accept', nat: '', routing: 'main', tls_profile: 'inspect',
        ssh_profile: 'default-ssh', detection_profile: 'detect', content_profile: 'capture', auth_profile: 'legacy-auth',
        dns_profile: 'resolver', script_profile: 'audit',
      }],
      addresses: [
        {id: 'address-0', name: 'office', type: 'cidr', value: '10.0.0.0/24'},
        {id: 'address-1', name: 'internet', type: 'fqdn', value: 'example.test'},
      ],
      ports: [{id: 'port-0', name: 'https', start: 443, end: 443}],
      protocols: [{id: 'protocol-0', name: 'tcp', number: 6}],
      profiles: [
        {
          id: 'tls-0', name: 'inspect', type: 'tls', routing: null,
          tls: {
            inspect: true, use_pfs: true, left_use_pfs: true, right_use_pfs: true,
            left_disable_reuse: false, right_disable_reuse: false,
            allow_untrusted_issuers: false, allow_invalid_certificates: false,
            allow_self_signed: false, certificate_transparency: true, ocsp_stapling: true,
            ocsp_mode: 1, ocsp_stapling_mode: 1, block_alpn: false,
            sni_based_certificates: true, ip_based_certificates: true,
            only_custom_certificates: false, no_fallback_bypass: true,
            sni_filter_uses_dns_cache: true, sni_filter_uses_dns_domain_tree: true,
            redirect_warning_ports: [443, 44443], failed_certificate_replacement: true,
            failed_certificate_override: false, failed_certificate_override_timeout: 600,
            failed_certificate_override_timeout_type: 0,
            ssl_key_log: false, client_hello_timeout_ms: 3000, handshake_timeout_ms: 10000,
            sni_bypass_entries: 2, client_certificate_action: 'use_configured', alerts: 'unusual',
          },
          detection: null,
          content: null,
          ssh: null,
          dns: null,
          script: null,
          authentication: null,
        },
        {
          id: 'routing-0', name: 'main', type: 'routing',
          routing: {
            destination_addresses: ['internet'], destination_ports: ['https'],
            load_balancing_method: 'round-robin', rewrite_sni: '', rewrite_sni_to: '',
          },
          tls: null,
          detection: null,
          content: null,
          ssh: null,
          dns: null,
          script: null,
          authentication: null,
        },
        {
          id: 'detection-0', name: 'detect', type: 'detection', routing: null, tls: null,
          detection: {mode: 1, engines_enabled: true, knowledge_base_enabled: false},
          content: null, ssh: null, dns: null, script: null, authentication: null,
        },
        {
          id: 'dns-0', name: 'resolver', type: 'dns', routing: null, tls: null,
          detection: null, content: null, ssh: null,
          dns: {match_request_id: true, randomize_id: true, cached_responses: false},
          script: null, authentication: null,
        },
        {
          id: 'content-0', name: 'capture', type: 'content', routing: null, tls: null,
          detection: null,
          content: {
            write_payload: false, write_format: 'pcap_single', webhook_enabled: true,
            webhook_locks_traffic: false, ja4_tls_client_hello: true,
            ja4_tls_client_hello_ignores_sni: false, ja4_tls_server_hello: true,
            ja4_http: false, session_filter_configured: true, rule_count: 2,
            rules: [
              {id: 'content-rule-0-0', match_configured: true, replacement_configured: true,
               replacement_has_value: false, fill_length: true, replace_each_nth: 0},
              {id: 'content-rule-0-1', match_configured: true, replacement_configured: true,
               replacement_has_value: true, fill_length: false, replace_each_nth: 3},
            ],
          },
          ssh: null, dns: null, script: null, authentication: null,
        },
        {
          id: 'ssh-0', name: 'default-ssh', type: 'ssh', routing: null, tls: null,
          detection: null, content: null,
          ssh: {
            host_key_configured: true, host_key_policy: 'strict', shell: true,
            exec: false, subsystem: true, pty: true, environment: false,
            local_forward: false, remote_forward: false, x11: false, agent: false,
          },
          dns: null, script: null, authentication: null,
        },
        {
          id: 'script-0', name: 'audit', type: 'script', routing: null, tls: null,
          detection: null, content: null, ssh: null, dns: null,
          script: {runtime: 'python', module_path_configured: true}, authentication: null,
        },
        {
          id: 'authentication-0', name: 'legacy-auth', type: 'authentication', routing: null, tls: null,
          detection: null, content: null, ssh: null, dns: null, script: null,
          authentication: {authenticate: true, resolve: true, identity_count: 2, deprecated: true},
        },
      ],
      settings: {
        accept_tproxy: true, accept_redirect: true, accept_socks: false,
        accept_http_connect: true, accept_api: true, extended_local_destination_protection: true,
        policy_fail_open: false,
        access_request_fail_open: false,
        workers: {plaintext: 2, tls: 4, udp: 1, dtls: 1, quic: 0, socks: 0, http_connect: 1},
        ports: {plaintext: 50080, tls: 50443, udp: 50080, dtls: 50443, quic: 443, socks: 1080, http_connect: 3128},
        ocsp_status_ttl: 1800, crl_status_ttl: 86400,
        logging: {
          default_write_payload: false, payload_directory_configured: true, pcap_single_quota: 100,
          level: 6, file_configured: true, console: true, ssl_key_file_configured: true,
          syslog_server_configured: false, syslog_port: 514, syslog_facility: 23,
          syslog_level: 6, syslog_family: 4,
        },
        auxiliary: {
          udp_quick_port_count: 1, udp_quick_ports: ['0'], certificates_path_configured: true,
          certificate_password_configured: true, certificate_transparency_log_configured: true,
          ca_bundle_path_configured: true, ca_bundle_file_configured: false,
          messages_directory_configured: true, payload_file_prefix_configured: false,
          payload_file_suffix_configured: false, cli_port: 50000, cli_password_configured: false,
          web_rating_key_configured: false, admin_group_configured: true,
          tuning: {
            host_buffer_min: 2048, host_buffer_max_multiplier: 1024, host_write_full: 200000,
            host_io_batch: 262144, tls_write_chunk: 20480, host_open_timeout: 7,
            host_idle_timeout: 3600, neighbor_cache_size: 8000,
          },
          thread_pool_logging: false, socks_async_dns: true,
          socks_ip_version_mixing: true, socks_prefer_ipv6: false,
        },
        tls_autodetect: true, tls_autodetect_harder: false, kernel_tls: false,
        nameserver_count: 2, nameservers: ['192.0.2.53', '2001:db8::53'],
        http_api: {
          key_count: 1, allowed_ip_count: 1, allowed_ips: ['127.0.0.1'],
          key_timeout: 3600, port: 55555, key_extend_on_access: true,
          loopback_only: true, pam_login: false, allow_api_header: false,
          bind_address_configured: true, bind_interface_configured: false,
        },
        webhook: {
          enabled: false, tls_verify: true, url_configured: false, sift_enabled: false,
          sift_url_configured: true, sift_tenant_configured: true, sift_instance_configured: false,
          sift_payload_limit_per_direction: 262144, sift_lored_mode: 'disabled',
          sift_lored_include_url: false, hostid_configured: false,
          bind_interface_configured: false, api_override: false, ping_interval: 120,
          nbr_update_interval: 900, nbr_tag_refresh_age: 300, task_debug: false,
          task_debug_dump: false,
        },
      },
      debug: {
        log_data_crc: false, log_sockets: false, log_online_cx_name: false,
        log_srclines: false, log_srclines_always: false, module_override_count: 1,
        module_overrides: [{name: 'proxy', kind: 'integer', value: 6}],
      },
      captures: {
        local: {
          enabled: false, directory_configured: true, file_prefix_configured: true,
          file_suffix_configured: true, format: 'pcap_single', quota_mib: 1024,
        },
        remote: {
          enabled: false, tunnel_type: 'gre', gre_format: 'traffic',
          destination_configured: false, ttl: 1, bind_interface_configured: false,
        },
        calculate_checksums: true,
      },
      security_assets: {
        certificate_authorities: [{id: 'certificate-authority-0', name: 'default', path_configured: true}],
        certificate_authority_count: 1, certificate_authority_path_count: 1,
        starttls_signature_count: 1, starttls_flow_step_count: 2,
        detection_signature_count: 1, detection_flow_step_count: 1,
        signatures: [
          {
            id: 'starttls-signature-0', kind: 'starttls', category: 'mail', name: 'smtp/starttls',
            side: 'client', severity: 0, group: '', enables: '', engine: '',
            flow: [
              {id: 'starttls-signature-0-flow-0', side: 'r', type: 'regex', expression_configured: true,
               bytes_start: 0, bytes_max: 16},
              {id: 'starttls-signature-0-flow-1', side: 'w', type: 'regex', expression_configured: true,
               bytes_start: 0, bytes_max: 512},
            ],
          },
          {
            id: 'detection-signature-0', kind: 'detection', category: 'www', name: 'http/request',
            side: 'client', severity: 4, group: 'base', enables: 'http', engine: 'http1',
            flow: [{
              id: 'detection-signature-0-flow-0', side: 'r', type: 'regex', expression_configured: true,
              bytes_start: 0, bytes_max: 200,
            }],
          },
        ],
      },
      augment_support: false,
      value_origins: [],
      }});
    });
  }
}

async function expectNoWcagViolations(page: Page): Promise<void> {
  const result = await new AxeBuilder({page})
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'])
    .analyze();
  const summary = result.violations.map(violation =>
    `${violation.id}: ${violation.help} (${violation.nodes.length} node${violation.nodes.length === 1 ? '' : 's'})`,
  ).join('\n');
  expect(result.violations, summary).toEqual([]);
}

test('loads authenticated runtime configuration and saves an atomic policy draft', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'}, true);
  await page.goto('/');
  await page.getByRole('button', {name: 'Policy', exact: true}).click();
  await expect(page.getByRole('button', {name: /Policy 1 office internet accept/i})).toBeVisible();
  await page.getByRole('button', {name: /Policy 1 office internet accept/i}).click();
  const editor = page.getByRole('dialog', {name: 'Edit Policy 1'});
  await expect(editor.getByText('Validation ready')).toBeVisible();
  await editor.getByLabel('Name').fill('Office outbound');
  await editor.locator('#policy-enabled-policy-0').uncheck();
  await editor.getByLabel('Destinations').fill('internet, backup');
  await editor.getByLabel('Source ports').fill('any, https');
  await editor.getByLabel('Features').fill('sinkhole, audit');
  await editor.getByLabel('NAT', {exact: true}).fill('masquerade');
  const action = editor.getByLabel('Action');
  await action.fill('reject');
  await editor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(editor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 18 changes')).toBeVisible();
  await expect(page.getByText('Config: Ready')).toBeVisible();
  await editor.getByRole('button', {name: /tcp/i}).click();
  const protocolEditor = page.getByRole('dialog', {name: 'Edit tcp'});
  await expect(protocolEditor).toBeVisible();
  await protocolEditor.getByLabel('IP protocol number').fill('17');
  await protocolEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(protocolEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 20 changes')).toBeVisible();
  await protocolEditor.getByRole('button', {name: 'Cancel'}).click();
  await editor.getByRole('button', {name: 'https', exact: true}).click();
  const portEditor = page.getByRole('dialog', {name: 'Edit https'});
  await expect(portEditor).toBeVisible();
  await portEditor.getByLabel('Start').fill('9000');
  await portEditor.getByLabel('End').fill('8000');
  await portEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(portEditor.getByText(/valid port range from 0 to 65535/i)).toBeVisible();
  await expect(page.getByText('Draft: 20 changes')).toBeVisible();
  await portEditor.getByLabel('Start').fill('8443');
  await portEditor.getByLabel('End').fill('8443');
  await portEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(portEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 23 changes')).toBeVisible();
  await portEditor.getByRole('button', {name: 'Cancel'}).click();
  await editor.getByRole('button', {name: 'inspect', exact: true}).click();
  const tlsEditor = page.getByRole('dialog', {name: 'Edit inspect'});
  await expect(tlsEditor).toBeVisible();
  await expect(tlsEditor.getByLabel('Allow invalid certificates')).toHaveValue('false');
  await tlsEditor.getByLabel('Client hello timeout').fill('0');
  await tlsEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(tlsEditor.getByText(/TLS timeouts and policy selections are invalid/i)).toBeVisible();
  await expect(page.getByText('Draft: 23 changes')).toBeVisible();
  await tlsEditor.getByLabel('Client hello timeout').fill('4000');
  await tlsEditor.getByLabel('Allow invalid certificates').selectOption('true');
  await tlsEditor.getByLabel('Downstream PFS').selectOption('false');
  await tlsEditor.getByLabel('OCSP certificate checks').selectOption('2');
  await tlsEditor.getByLabel('OCSP stapling policy').selectOption('2');
  await tlsEditor.getByLabel('Certificate warning ports').fill('443, 8443');
  await tlsEditor.getByLabel('Certificate failure override').selectOption('true');
  await tlsEditor.getByLabel('Override timeout', {exact: true}).fill('900');
  await tlsEditor.getByLabel('Override timeout behavior').selectOption('1');
  await tlsEditor.getByLabel('Alerts').selectOption('all');
  await tlsEditor.getByLabel('SNI bypass list', {exact: true}).selectOption('replace');
  await tlsEditor.getByLabel('SNI bypass list replacement').fill('["internal.example", "*.private.example"]');
  await tlsEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(tlsEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 55 changes')).toBeVisible();
  await expect(tlsEditor.getByLabel('SNI bypass list', {exact: true})).toHaveValue('unchanged');
  await expect(tlsEditor.getByLabel('SNI bypass list replacement')).toHaveValue('');
  await expect(tlsEditor.getByText(/Current SNI bypass values stay inside the GUI core/i)).toBeVisible();
  await tlsEditor.getByRole('button', {name: 'Cancel'}).click();
  await editor.getByRole('button', {name: 'capture', exact: true}).click();
  const contentEditor = page.getByRole('dialog', {name: 'Edit capture'});
  await contentEditor.getByLabel('Payload capture').selectOption('true');
  await contentEditor.getByLabel('Capture format').selectOption('smcap');
  await contentEditor.getByLabel('Webhook traffic lock').selectOption('true');
  await contentEditor.getByLabel('JA4 HTTP').selectOption('true');
  await contentEditor.getByLabel('Session filter', {exact: true}).selectOption('replace');
  await contentEditor.getByLabel('Session filter replacement').fill('policy == "office-secret"');
  await contentEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(contentEditor.getByText('Saved to draft')).toBeVisible();
  await expect(contentEditor.getByLabel('Session filter', {exact: true})).toHaveValue('unchanged');
  await expect(contentEditor.getByLabel('Session filter replacement')).toHaveValue('');
  await expect(contentEditor.getByRole('group', {name: 'Content rules'}).getByRole('button')).toHaveCount(2);
  await expect(page.getByText('Draft: 65 changes')).toBeVisible();
  await contentEditor.getByRole('button', {name: 'Cancel'}).click();
  await editor.getByRole('button', {name: 'default-ssh', exact: true}).click();
  const sshEditor = page.getByRole('dialog', {name: 'Edit default-ssh'});
  await expect(sshEditor.getByLabel('Host key', {exact: true})).toHaveValue('unchanged');
  await sshEditor.getByLabel('Host key', {exact: true}).selectOption('replace');
  await sshEditor.getByLabel('Host key replacement').fill('/etc/smithproxy/new-host-key');
  await sshEditor.getByLabel('Upstream host-key policy').selectOption('accept-new');
  await sshEditor.getByLabel('Exec').selectOption('pass');
  await sshEditor.getByLabel('Local forwarding').selectOption('pass');
  await sshEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(sshEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 77 changes')).toBeVisible();
  await expect(sshEditor.getByLabel('Host key', {exact: true})).toHaveValue('unchanged');
  await expect(sshEditor.getByLabel('Host key replacement')).toHaveValue('');
  await sshEditor.getByRole('button', {name: 'Cancel'}).click();
  await editor.getByRole('button', {name: 'audit', exact: true}).click();
  const scriptEditor = page.getByRole('dialog', {name: 'Edit audit'});
  await expect(scriptEditor.getByLabel('Module path', {exact: true})).toHaveValue('unchanged');
  await scriptEditor.getByLabel('Module path', {exact: true}).selectOption('replace');
  await scriptEditor.getByLabel('Module path replacement').fill('/opt/smithproxy/new-audit.py');
  await scriptEditor.getByLabel('Runtime').selectOption('go');
  await scriptEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(scriptEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 80 changes')).toBeVisible();
  await expect(scriptEditor.getByLabel('Module path', {exact: true})).toHaveValue('unchanged');
  await expect(scriptEditor.getByLabel('Module path replacement')).toHaveValue('');
  await scriptEditor.getByRole('button', {name: 'Cancel'}).click();
  await editor.getByRole('button', {name: 'legacy-auth', exact: true}).click();
  const authenticationEditor = page.getByRole('dialog', {name: 'Edit legacy-auth'});
  await expect(authenticationEditor.getByText('2 redacted entries · unchanged')).toBeVisible();
  await authenticationEditor.getByLabel('Authenticate').selectOption('false');
  await authenticationEditor.getByLabel('Resolve identities').selectOption('false');
  await authenticationEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(authenticationEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 83 changes')).toBeVisible();
  await authenticationEditor.getByRole('button', {name: 'Cancel'}).click();
  await editor.getByRole('button', {name: 'detect', exact: true}).click();
  const detectionEditor = page.getByRole('dialog', {name: 'Edit detect'});
  await detectionEditor.getByLabel('Detection phase').selectOption('2');
  await detectionEditor.getByLabel('L7 engines').selectOption('false');
  await detectionEditor.getByLabel('Knowledge base').selectOption('true');
  await detectionEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(detectionEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 87 changes')).toBeVisible();
  await detectionEditor.getByRole('button', {name: 'Cancel'}).click();
  await editor.getByRole('button', {name: 'resolver', exact: true}).click();
  const dnsEditor = page.getByRole('dialog', {name: 'Edit resolver'});
  await dnsEditor.getByLabel('Match request ID').selectOption('false');
  await dnsEditor.getByLabel('Randomize upstream ID').selectOption('false');
  await dnsEditor.getByLabel('Cached responses').selectOption('true');
  await dnsEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(dnsEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 91 changes')).toBeVisible();
  await dnsEditor.getByRole('button', {name: 'Cancel'}).click();
  await editor.getByRole('button', {name: 'main', exact: true}).click();
  const routingEditor = page.getByRole('dialog', {name: 'Edit main'});
  await routingEditor.getByLabel('Destination addresses').fill('internet, office');
  await routingEditor.getByLabel('Load balancing').selectOption('sticky-l4');
  await routingEditor.getByLabel('Rewrite SNI match').fill('old.example');
  await routingEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(routingEditor.getByText(/SNI rewrite requires both values/i)).toBeVisible();
  await expect(page.getByText('Draft: 91 changes')).toBeVisible();
  await routingEditor.getByLabel('Rewrite SNI target').fill('new.example');
  await routingEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(routingEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 97 changes')).toBeVisible();
  await routingEditor.getByRole('button', {name: 'internet', exact: true}).click();
  await expect(page.getByRole('dialog', {name: 'Edit internet'})).toBeVisible();
  await page.keyboard.press('Escape');
  await page.keyboard.press('Escape');
  await editor.getByRole('button', {name: 'office', exact: true}).click();
  const addressEditor = page.getByRole('dialog', {name: 'Edit office'});
  await expect(addressEditor).toBeVisible();
  await addressEditor.getByLabel('Address').fill('10.0.1.0/24');
  await addressEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(addressEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 100 changes')).toBeVisible();
  await addressEditor.getByRole('button', {name: 'Cancel'}).click();
  await expect(addressEditor).not.toBeVisible();
  await editor.getByRole('button', {name: 'Cancel'}).click();
  await expect(editor).not.toBeVisible();
  await page.getByRole('button', {name: 'System', exact: true}).click();
  const trustPosture = page.getByRole('article').filter({has: page.getByRole('heading', {name: 'Trust and signatures'})});
  await trustPosture.getByRole('button', {name: /default · path configured/i}).click();
  const authorityEditor = page.getByRole('dialog', {name: 'Edit default'});
  await authorityEditor.getByLabel('CA path', {exact: true}).selectOption('replace');
  await authorityEditor.getByLabel('CA path replacement').fill('/etc/smithproxy/private/new-default-ca');
  await authorityEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(authorityEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 102 changes')).toBeVisible();
  await expect(authorityEditor.getByLabel('CA path', {exact: true})).toHaveValue('unchanged');
  await expect(authorityEditor.getByLabel('CA path replacement')).toHaveValue('');
  await authorityEditor.getByRole('button', {name: 'Cancel'}).click();
  await page.getByRole('button', {name: 'Review draft · 102'}).click();
  await expect(page.getByRole('heading', {name: 'Workspace draft'})).toBeVisible();
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('address_objects.[0].value');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('10.0.1.0/24');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('routing.[0].dnat_lb_method');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('sticky-l4');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('detection_profiles.[0].mode');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('alg_dns_profiles.[0].cached_responses');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('tls_profiles.[0].allow_invalid_certs');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('tls_profiles.[0].redirect_warning_ports');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('443, 8443');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('tls_profiles.[0].ocsp_mode');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('tls_profiles.[0].sni_filter_bypass');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('content_profiles.[0].write_format');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('content_profiles.[0].rules_session_filter');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('policy.[0].sport');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('policy.[0].alg_dns_profile');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('ssh_profiles.[0].hostkey_policy');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('ssh_profiles.[0].host_key');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('script_profiles.[0].type');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('script_profiles.[0].script-file');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).not.toContainText('/etc/smithproxy/new-host-key');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).not.toContainText('/opt/smithproxy/new-audit.py');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).not.toContainText('internal.example');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).not.toContainText('office-secret');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('tls_ca.[0].path');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).not.toContainText('/etc/smithproxy/private/new-default-ca');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('auth_profiles.[0].authenticate');
  await page.getByRole('button', {name: 'Discard draft'}).click();
  await expect(page.getByRole('button', {name: 'Confirm discard 102 changes'})).toBeVisible();
  await expect(page.getByText('Draft: 102 changes')).toBeVisible();
  await page.getByRole('button', {name: 'Confirm discard 102 changes'}).click();
  await expect(page.getByText('Draft: 0 changes')).toBeVisible();
  await expect(page.getByText('No pending changes')).toBeVisible();
});

test('refreshes live configuration only outside an active edit transaction', async ({page}) => {
  const state: MockState = {smithproxy: 'ready', configFetches: 0};
  await mockSystemApi(page, state, true);
  await page.goto('/');
  await expect(page.getByText('Config: Ready')).toBeVisible();
  await expect.poll(() => state.configFetches).toBe(1);

  const advanceRefreshWindow = async () => page.evaluate(() => {
    const advanced = Date.now() + 31_000;
    Date.now = () => advanced;
  });
  await advanceRefreshWindow();
  await page.evaluate(() => window.dispatchEvent(new Event('online')));
  await expect.poll(() => state.configFetches).toBe(2);

  await page.getByRole('button', {name: 'Policy', exact: true}).click();
  await page.getByRole('button', {name: /Policy 1 office internet accept/i}).click();
  await expect(page.getByRole('dialog', {name: 'Edit Policy 1'})).toBeVisible();
  await advanceRefreshWindow();
  await page.evaluate(() => window.dispatchEvent(new Event('online')));
  await expect(page.locator('.statusbar')).toContainText('Config: Ready');
  await expect(page.locator('.statusbar')).toContainText('refresh paused');
  await expect.poll(() => state.configFetches).toBe(2);

  await page.getByRole('dialog', {name: 'Edit Policy 1'})
    .getByRole('button', {name: 'Cancel'}).click();
  await expect.poll(() => state.configFetches).toBe(3);
  await expect(page.locator('.statusbar')).not.toContainText('refresh paused');
});

test('recovers from a concurrent draft writer without losing either change set', async ({page}) => {
  const state: MockState = {
    smithproxy: 'ready',
    conflictNextDraftWrite: true,
    draftMutationVersions: [],
  };
  await mockSystemApi(page, state, true);
  await page.goto('/');
  await page.getByRole('button', {name: 'Policy', exact: true}).click();
  await page.getByRole('button', {name: /Policy 1 office internet accept/i}).click();

  const editor = page.getByRole('dialog', {name: 'Edit Policy 1'});
  await editor.getByLabel('Name').fill('Concurrent policy edit');
  await editor.getByRole('button', {name: 'Save to draft'}).click();

  await expect(editor.getByRole('status')).toContainText('HTTP 409');
  await expect(page.getByText('Draft: 1 changes')).toBeVisible();
  expect(state.draftMutationVersions).toEqual([0]);

  await editor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(editor.getByRole('status')).toHaveText('Saved to draft');
  expect(state.draftMutationVersions).toEqual([0, 1]);
  await expect(page.getByText('Draft: 19 changes')).toBeVisible();

  await editor.getByRole('button', {name: 'Cancel'}).click();
  await page.getByRole('button', {name: 'Review draft · 19'}).click();
  const changes = page.getByRole('table', {name: 'Pending draft changes'});
  await expect(changes).toContainText('settings.policy_fail_open');
  await expect(changes).toContainText('policy.[0].name');
  await expect(changes).toContainText('Concurrent policy edit');
});

test('opens a policy and its referenced address object', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'});
  await page.goto('/');
  await page.getByRole('button', {name: 'Policy', exact: true}).click();
  await page.getByRole('button', {name: /office office-net/i}).click();
  await expect(page.getByRole('dialog', {name: 'Edit office'})).toBeVisible();
  await expect(page.getByText(/temporary-office-access \(priority 100\)/i)).toBeVisible();
  await expect(page.getByText(/incident-response \(priority 200\)/i)).toBeVisible();
  const overlay = page.getByRole('region', {name: 'Effective value overlays'});
  await expect(overlay).toContainText('Persistent reject');
  await expect(overlay).toContainText('effective accept');
  await expect(overlay).toContainText('incident-response (priority 200): accept (active)');
  await expect(overlay).toContainText('The active layer owns this value');
  await expect(page.locator('#action-policy-office')).toHaveAttribute('readonly', '');

  await page.getByRole('button', {name: 'office-net', exact: true}).click();
  const addressEditor = page.getByRole('dialog', {name: 'Edit office-net'});
  await expect(addressEditor).toBeVisible();
  await expect(page.getByText('This shared object is used by 4 configuration entries.')).toBeVisible();

  const policyEditor = page.getByRole('dialog', {name: 'Edit office', exact: true, includeHidden: true});
  await expect(policyEditor).toHaveAttribute('inert', '');
  await expect(addressEditor).not.toHaveAttribute('inert', '');

  const firstFocusable = addressEditor.getByRole('button', {name: 'Enter focus mode'});
  const lastFocusable = addressEditor.getByRole('button', {name: 'Save to draft'});
  await firstFocusable.focus();
  await page.keyboard.press('Shift+Tab');
  await expect(lastFocusable).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(firstFocusable).toBeFocused();

  await addressEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(page.getByText('Draft: 1 changes')).toBeVisible();
  await expect(addressEditor.getByRole('status')).toHaveText('Saved to draft');

  await page.keyboard.press('Escape');
  await expect(addressEditor).not.toBeVisible();
  await expect(page.getByRole('dialog', {name: 'Edit office'})).toBeVisible();
});

test('restores drawer routes and manages focus across the chain', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'});
  await page.goto('/');
  await page.getByRole('button', {name: 'Policy', exact: true}).click();
  await page.getByRole('button', {name: /office office-net/i}).click();
  await expect(page.locator('#policy-name-policy-office')).toBeFocused();
  await expect.poll(() => new URL(page.url()).searchParams.get('edit')).toBe('policy:policy-office');
  const workspaceBox = await page.locator('.workspace').boundingBox();
  const policyBox = await page.locator('.drawer').first().boundingBox();
  expect(workspaceBox).not.toBeNull();
  expect(policyBox).not.toBeNull();
  expect(policyBox!.width / workspaceBox!.width).toBeGreaterThanOrEqual(.79);
  expect(policyBox!.width / workspaceBox!.width).toBeLessThanOrEqual(.81);

  const reference = page.getByRole('button', {name: 'office-net', exact: true});
  await reference.click();
  await expect(page.locator('#address-name-address-office-net')).toBeFocused();
  await expect.poll(() => new URL(page.url()).searchParams.get('edit')).toBe(
    'policy:policy-office,address:address-office-net',
  );
  const addressBox = await page.locator('.drawer').nth(1).boundingBox();
  expect(addressBox).not.toBeNull();
  const drawerLeft = await page.locator('.drawer').evaluateAll(elements =>
    elements.map(element => Number.parseFloat(getComputedStyle(element).left)));
  expect(drawerLeft[1] - drawerLeft[0]).toBeGreaterThanOrEqual(51);
  expect(drawerLeft[1] - drawerLeft[0]).toBeLessThanOrEqual(53);

  const addressEditor = page.getByRole('dialog', {name: 'Edit office-net'});
  await addressEditor.getByRole('button', {name: 'Enter focus mode'}).click();
  await expect(addressEditor).toHaveCSS('left', '0px');
  await page.keyboard.press('Escape');
  await expect(addressEditor).not.toBeVisible();
  await expect(reference).toBeFocused();
  await expect.poll(() => new URL(page.url()).searchParams.get('edit')).toBe('policy:policy-office');

  await reference.click();
  await page.reload();
  await expect(page.getByRole('dialog', {name: 'Edit office', exact: true, includeHidden: true})).toBeVisible();
  await expect(page.getByRole('dialog', {name: 'Edit office-net'})).toBeVisible();
  await expect(page.locator('#address-name-address-office-net')).toBeFocused();
  await page.goBack();
  await expect(page.getByRole('dialog', {name: 'Edit office-net'})).not.toBeVisible();
  await expect(page.getByRole('dialog', {name: 'Edit office'})).toBeVisible();
});

test('requires an explicit decision before closing unsaved drawer changes', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'});
  await page.goto('/');
  await page.getByRole('button', {name: 'Policy', exact: true}).click();
  const policyRow = page.getByRole('button', {name: /office office-net/i});
  await policyRow.click();

  const editor = page.getByRole('dialog', {name: 'Edit office'});
  await editor.getByLabel('Name').fill('Unsaved policy');
  await expect(editor.getByRole('status')).toHaveText('Unsaved changes');
  await expect.poll(() => page.evaluate(() => {
    const event = new Event('beforeunload', {cancelable: true});
    window.dispatchEvent(event);
    return event.defaultPrevented;
  })).toBe(true);
  await page.keyboard.press('Escape');

  await expect(editor).toBeVisible();
  await expect(editor.getByRole('alert')).toHaveText('Discard unsaved changes in this editor?');
  await expect(editor.getByRole('button', {name: 'Keep editing'})).toBeFocused();
  await expectNoWcagViolations(page);
  await editor.getByRole('button', {name: 'Keep editing'}).click();
  await expect(editor.getByRole('status')).toHaveText('Unsaved changes');

  await page.goBack();
  await expect.poll(() => new URL(page.url()).searchParams.get('edit')).toBe('policy:policy-office');
  await expect(editor.getByRole('alert')).toHaveText('Discard unsaved changes in this editor?');
  await editor.getByRole('button', {name: 'Discard changes'}).click();
  await expect(editor).not.toBeVisible();
  await expect(policyRow).toBeFocused();

  await policyRow.click();
  const reopened = page.getByRole('dialog', {name: 'Edit office'});
  await reopened.getByLabel('Name').fill('Saved policy');
  await reopened.getByRole('button', {name: 'Save to draft'}).click();
  await expect(reopened.getByRole('status')).toHaveText('Saved to draft');
  await expect.poll(() => page.evaluate(() => {
    const event = new Event('beforeunload', {cancelable: true});
    window.dispatchEvent(event);
    return event.defaultPrevented;
  })).toBe(false);
  await page.keyboard.press('Escape');
  await expect(reopened).not.toBeVisible();
});

test('shows live Smithproxy status transitions', async ({page}) => {
  const state: MockState = {smithproxy: 'ready'};
  await mockSystemApi(page, state);
  await page.goto('/');

  await expect(page.getByText('Core: Online')).toBeVisible();
  await expect(page.getByText('Smithproxy: Ready')).toBeVisible();
  await expect(page.getByText('Probe latency').locator('..').getByText('12 ms', {exact: true})).toBeVisible();
  await expect(page.getByRole('region', {name: 'Probe history'})).toBeVisible();
  const activeAlerts = page.getByRole('region', {name: 'Active operational alerts'});
  await expect(activeAlerts.getByText('● Clear', {exact: true})).toBeVisible();
  await expect(page.getByText(/control-plane health and listener counters are live/i)).toBeVisible();
  await expect(page.getByRole('region', {name: 'Runtime metrics summary'}).getByText('4', {exact: true})).toBeVisible();
  const tlsCache = page.getByRole('region', {name: 'TLS interception cache'});
  await expect(tlsCache.getByText('42', {exact: true})).toBeVisible();
  await expect(tlsCache.getByRole('progressbar', {name: 'TLS cache utilization'}))
    .toHaveAttribute('aria-valuenow', '4.2');

  await page.getByRole('button', {name: 'Monitoring', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Listener monitoring'})).toBeVisible();
  await expect(page.getByRole('cell', {name: 'tcp'}).first()).toBeVisible();
  await expect(page.getByRole('cell', {name: 'tls'}).first()).toBeVisible();
  const activity = page.getByRole('region', {name: 'Session activity'});
  await expect(activity.getByRole('heading', {name: 'Live session activity'})).toBeVisible();
  await expect(activity.getByText(/no endpoints, session ids, or policy names/i)).toBeVisible();
  await expect(activity.getByText('3.84 kB/s')).toBeVisible();
  const runtimeHistory = page.getByRole('region', {name: 'Runtime history'});
  await expect(runtimeHistory.getByRole('img', {name: /Active session trend. Peak 4 sessions/i})).toBeVisible();
  await expect(runtimeHistory.getByRole('img', {name: /Aggregate throughput trend/i})).toBeVisible();
  await expect(runtimeHistory.getByText(/no endpoints, session identifiers, or policy names/i)).toBeVisible();

  state.smithproxy = 'unreachable';
  await page.evaluate(() => window.dispatchEvent(new Event('online')));
  await expect(page.getByText('Smithproxy: Unreachable')).toBeVisible();
  await expect(activeAlerts.getByText('Control plane is unavailable', {exact: true})).toBeVisible();

  state.smithproxy = 'ready';
  await page.evaluate(() => window.dispatchEvent(new Event('online')));
  await expect(page.getByText('Smithproxy: Ready')).toBeVisible();
  await expect(activeAlerts.getByText('● Clear', {exact: true})).toBeVisible();
  const health = page.getByRole('region', {name: 'Operational health matrix'});
  await expect(health.getByRole('heading', {name: 'Control plane'})).toBeVisible();
  await expect(health.getByRole('heading', {name: 'TLS cache'})).toBeVisible();
  const analysis = page.getByLabel('Probe latency analysis');
  await expect(analysis.getByText('11 ms', {exact: true})).toBeVisible();
  await expect(analysis.getByText('12 ms', {exact: true})).toHaveCount(2);
  await expect(analysis.getByText('0', {exact: true})).toBeVisible();
});

test('loads independent monitoring surfaces concurrently', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'});
  const endpoints = [
    '/api/v1/metrics/summary',
    '/api/v1/sessions/activity',
    '/api/v1/tls/cache/summary',
    '/api/v1/network/neighbors/summary',
    '/api/v1/events/recent',
    '/api/v1/alerts',
  ];
  const pending = new Set(endpoints);
  let release: () => void = () => undefined;
  const barrier = new Promise<void>(resolve => { release = resolve; });
  for (const endpoint of endpoints) {
    await page.route(`**${endpoint}`, async route => {
      pending.delete(endpoint);
      if (pending.size === 0) release();
      await barrier;
      await route.fallback();
    });
  }

  await page.goto('/');
  await expect(page.getByRole('region', {name: 'Runtime metrics summary'})).toContainText('19');
  await expect(page.getByRole('region', {name: 'Active operational alerts'})).toContainText('Clear');
  expect(pending.size).toBe(0);
});

test('exposes network, object, and system vertical slices', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'});
  await page.goto('/');

  await page.getByRole('button', {name: 'Network', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Listener workload'})).toBeVisible();
  const neighborhood = page.getByRole('region', {name: 'Neighborhood activity'});
  await expect(neighborhood.getByText('8', {exact: true})).toBeVisible();
  await expect(neighborhood.getByText(/hostnames, tags, labels, and per-endpoint timelines remain/i)).toBeVisible();
  await expect(page.getByRole('heading', {name: 'tcp'})).toBeVisible();
  await expect(page.getByLabel('Network listeners').getByText('3', {exact: true})).toBeVisible();

  await page.getByRole('button', {name: 'Objects', exact: true}).click();
  await expect(page.getByRole('group', {name: 'Address objects'})).toBeVisible();
  await expect(page.getByRole('group', {name: 'Port objects'})).toBeVisible();
  await expect(page.getByRole('group', {name: 'Protocol objects'})).toBeVisible();
  await expect(page.getByRole('group', {name: 'Profiles and routing'})).toBeVisible();
  await page.getByRole('button', {name: /office-net subnet/i}).click();
  await expect(page.getByRole('dialog', {name: 'Edit office-net'})).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByRole('group', {name: 'Port objects'}).getByRole('button', {name: /https Port range 443/i}).click();
  await expect(page.getByRole('dialog', {name: 'Edit https'})).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByRole('group', {name: 'Protocol objects'}).getByRole('button', {name: /tcp IP protocol 6/i}).click();
  await expect(page.getByRole('dialog', {name: 'Edit tcp'})).toBeVisible();
  await page.keyboard.press('Escape');
  const profiles = page.getByRole('group', {name: 'Profiles and routing'});
  await profiles.getByRole('button', {name: /default detection Typed details/i}).click();
  await expect(page.getByRole('dialog', {name: 'Edit default'}).getByLabel('Detection phase')).toHaveValue('1');
  await page.keyboard.press('Escape');
  await profiles.getByRole('button', {name: /capture content Typed details/i}).click();
  const contentEditor = page.getByRole('dialog', {name: 'Edit capture'});
  await expect(contentEditor.getByRole('group', {name: 'Content rules'}).getByRole('button')).toHaveCount(2);
  await expect(contentEditor.getByText(/Current session filters and all content-rule payloads stay inside/i)).toBeVisible();
  await page.keyboard.press('Escape');
  await profiles.getByRole('button', {name: /default-ssh ssh Typed details/i}).click();
  const sshEditor = page.getByRole('dialog', {name: 'Edit default-ssh'});
  await expect(sshEditor.getByLabel('Host key', {exact: true})).toHaveValue('unchanged');
  await expect(sshEditor.getByLabel('Upstream host-key policy')).toHaveValue('strict');
  await page.keyboard.press('Escape');
  await profiles.getByRole('button', {name: /safe-dns dns Typed details/i}).click();
  await expect(page.getByRole('dialog', {name: 'Edit safe-dns'}).getByText('Randomize upstream ID')).toBeVisible();
  await page.keyboard.press('Escape');
  await profiles.getByRole('button', {name: /audit script Typed details/i}).click();
  const scriptEditor = page.getByRole('dialog', {name: 'Edit audit'});
  await expect(scriptEditor.getByLabel('Module path', {exact: true})).toHaveValue('unchanged');
  await expect(scriptEditor.getByLabel('Runtime')).toHaveValue('python');
  await page.keyboard.press('Escape');
  await profiles.getByRole('button', {name: /legacy-auth authentication Typed details/i}).click();
  const authenticationEditor = page.getByRole('dialog', {name: 'Edit legacy-auth'});
  await expect(authenticationEditor.getByText('Deprecated compatibility profile')).toBeVisible();
  await expect(authenticationEditor.getByText('2 redacted entries · unchanged')).toBeVisible();
  await expect(authenticationEditor.getByLabel('Authenticate')).toHaveValue('true');
  await page.keyboard.press('Escape');

  await expect(page.getByRole('group', {name: 'Address objects'})).toHaveCSS('border-radius', '4px');

  await page.getByRole('button', {name: 'Logs', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Operational events'})).toBeVisible();
  const events = page.getByRole('list', {name: 'Operational events'});
  await expect(events.getByText('Smithproxy control plane is reachable')).toBeVisible();
  await expect(page.getByText(/does not parse the administrative CLI/i)).toBeVisible();

  await page.getByRole('button', {name: 'System', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'System integration'})).toBeVisible();
  await expect(page.getByText('Smithproxy key')).toBeVisible();
  await expect(page.getByText('Never exposed')).toBeVisible();
  await expect(page.getByRole('heading', {name: 'Traffic admission'})).toBeVisible();
  await expect(page.getByText('Fail closed')).toHaveCount(2);
  await expect(page.getByRole('heading', {name: 'Smithproxy API posture'})).toBeVisible();
  await expect(page.getByRole('heading', {name: 'Webhook posture'})).toBeVisible();
  const capturePosture = page.getByRole('article').filter({has: page.getByRole('heading', {name: 'Capture posture'})});
  await expect(capturePosture).toBeVisible();
  await expect(capturePosture.getByText('pcap_single / 1024 MiB')).toBeVisible();
  const trustPosture = page.getByRole('article').filter({has: page.getByRole('heading', {name: 'Trust and signatures'})});
  await expect(trustPosture).toBeVisible();
  await expect(trustPosture.locator('dt', {hasText: 'STARTTLS signatures'}).locator('xpath=following-sibling::dd[1]'))
    .toHaveText('1');
  await expect(trustPosture.locator('dt', {hasText: 'Detection signatures'}).locator('xpath=following-sibling::dd[1]'))
    .toHaveText('1');
  await expect(trustPosture.getByText(/paths and expressions use write-only controls/i)).toBeVisible();
  await trustPosture.getByText('Detection signatures', {exact: true}).last().click();
  await trustPosture.getByRole('button', {name: /http\/request · 1 flow step/i}).click();
  const signatureEditor = page.getByRole('dialog', {name: 'Edit http/request'});
  await expect(signatureEditor.getByLabel('Engine')).toHaveValue('http1');
  await signatureEditor.getByRole('button', {name: /1\. R · regex/i}).click();
  const flowEditor = page.getByRole('dialog', {name: 'Edit Flow R'});
  await expect(flowEditor.getByLabel('Expression', {exact: true})).toHaveValue('unchanged');
  await expect(flowEditor.getByText(/never serialized to the browser/i)).toBeVisible();
  await flowEditor.getByRole('button', {name: 'Cancel'}).click();
  await signatureEditor.getByRole('button', {name: 'Cancel'}).click();
  await trustPosture.getByRole('button', {name: /default · path configured/i}).click();
  const authorityEditor = page.getByRole('dialog', {name: 'Edit default'});
  await expect(authorityEditor.getByLabel('CA path', {exact: true})).toHaveValue('unchanged');
  await expect(authorityEditor.getByText(/current certificate-authority path stays inside/i)).toBeVisible();
});

test('saves typed system and capture settings without exposing redacted values', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'}, true);
  await page.goto('/');
  await page.getByRole('button', {name: 'System', exact: true}).click();

  const trafficCard = page.getByRole('article').filter({
    has: page.getByRole('heading', {name: 'Traffic admission'}),
  });
  await expect(trafficCard).toContainText('Local destination protection');
  await expect(trafficCard).toContainText('Enforced');
  await trafficCard.getByRole('button', {name: 'Edit'}).click();
  const settingsEditor = page.getByRole('dialog', {name: 'Edit System settings'});
  await settingsEditor.getByLabel('Policy failure').selectOption('true');
  await settingsEditor.getByLabel('Protect local explicit-proxy destinations').selectOption('false');
  await settingsEditor.getByLabel('TLS workers', {exact: true}).fill('8');
  await settingsEditor.getByLabel('TLS port', {exact: true}).fill('5443');
  await settingsEditor.getByLabel('API header access').selectOption('true');
  await settingsEditor.getByLabel('API token TTL (seconds)').fill('900');
  await settingsEditor.getByLabel('API port').fill('55580');
  await settingsEditor.getByLabel('Refresh tokens on access').selectOption('false');
  await settingsEditor.getByLabel('API bind address', {exact: true}).selectOption('replace');
  await settingsEditor.getByLabel('API bind address replacement').fill('192.0.2.77');
  await settingsEditor.getByLabel('API bind interface', {exact: true}).selectOption('replace');
  await settingsEditor.getByLabel('API bind interface replacement').fill('private-api0');
  await settingsEditor.getByLabel('Socket event logging').selectOption('true');
  await settingsEditor.getByLabel('Log level', {exact: true}).fill('7');
  await settingsEditor.getByLabel('CLI port', {exact: true}).fill('50001');
  await settingsEditor.getByLabel('Nameservers').fill('192.0.2.53, 2001:db8::53, resolver.example');
  await settingsEditor.getByLabel('UDP quick ports').fill('0, 53, 443');
  await settingsEditor.getByLabel('HTTP API allowed IPs').fill('127.0.0.1, 192.0.2.0/24');
  await settingsEditor.getByLabel('Webhook URL', {exact: true}).selectOption('replace');
  await settingsEditor.getByLabel('Webhook URL replacement').fill('https://hooks.example.test/smithproxy');
  await settingsEditor.getByLabel('Sift payload limit per direction').fill('524288');
  await settingsEditor.getByLabel('Sift LoreD enrichment').selectOption('required');
  await settingsEditor.getByLabel('Allow LoreD URL disclosure').selectOption('true');
  await settingsEditor.getByLabel('Sift URL', {exact: true}).selectOption('replace');
  await settingsEditor.getByLabel('Sift URL replacement').fill('http://private-sift.test/webhook');
  await settingsEditor.getByLabel('Sift tenant ID', {exact: true}).selectOption('replace');
  await settingsEditor.getByLabel('Sift tenant ID replacement').fill('private-tenant');
  await settingsEditor.getByLabel('Sift instance ID', {exact: true}).selectOption('replace');
  await settingsEditor.getByLabel('Sift instance ID replacement').fill('private-instance');
  await settingsEditor.getByLabel('Webhook host ID', {exact: true}).selectOption('replace');
  await settingsEditor.getByLabel('Webhook host ID replacement').fill('private-host');
  await settingsEditor.getByLabel('Webhook bind interface', {exact: true}).selectOption('replace');
  await settingsEditor.getByLabel('Webhook bind interface replacement').fill('private-webhook0');
  await settingsEditor.getByLabel('Initial host buffer (bytes)').fill('4096');
  await settingsEditor.getByLabel('Certificate transparency log file', {exact: true}).selectOption('replace');
  await settingsEditor.getByLabel('Certificate transparency log file replacement').fill('/private/ct-log.cnf');
  await settingsEditor.getByLabel('CA bundle file', {exact: true}).selectOption('replace');
  await settingsEditor.getByLabel('CA bundle file replacement').fill('/private/ca-bundle.pem');
  await settingsEditor.getByLabel('Administration group', {exact: true}).selectOption('replace');
  await settingsEditor.getByLabel('Administration group replacement').fill('private-admins');
  await settingsEditor.getByLabel('Certificate password', {exact: true}).selectOption('replace');
  await settingsEditor.getByLabel('Certificate password replacement').fill('new-private-password');
  await settingsEditor.getByLabel('Syslog server', {exact: true}).selectOption('clear');
  await settingsEditor.getByLabel('HTTP API keys', {exact: true}).selectOption('replace');
  await settingsEditor.getByLabel('HTTP API keys replacement').fill('["new-api-key", "overlap-api-key"]');
  await settingsEditor.getByLabel('proxy module override').fill('8');
  await expect(settingsEditor.getByText('Keep empty', {exact: true})).toHaveCount(11);
  await settingsEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(settingsEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 89 changes')).toBeVisible();
  await expect(settingsEditor.getByLabel('HTTP API keys replacement')).toHaveValue('');
  await expect(settingsEditor.getByLabel('HTTP API keys', {exact: true})).toHaveValue('unchanged');
  await settingsEditor.getByRole('button', {name: 'Cancel'}).click();

  const captureCard = page.getByRole('article').filter({
    has: page.getByRole('heading', {name: 'Capture posture'}),
  });
  await captureCard.getByRole('button', {name: 'Edit'}).click();
  const captureEditor = page.getByRole('dialog', {name: 'Edit Capture settings'});
  await captureEditor.getByLabel('Local capture').selectOption('true');
  await captureEditor.getByLabel('Local format').selectOption('smcap');
  await captureEditor.getByLabel('Tunnel TTL').fill('32');
  await captureEditor.getByLabel('Local directory', {exact: true}).selectOption('replace');
  await captureEditor.getByLabel('Local directory replacement').fill('/new/private/captures');
  await captureEditor.getByLabel('Remote destination', {exact: true}).selectOption('clear');
  await captureEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(captureEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 98 changes')).toBeVisible();
  await expect(captureEditor.getByLabel('Local directory replacement')).toHaveValue('');
  await captureEditor.getByRole('button', {name: 'Cancel'}).click();

  await page.getByRole('button', {name: 'Review draft · 98'}).click();
  const changes = page.getByRole('table', {name: 'Pending draft changes'});
  await expect(changes).toContainText('settings.ssl_workers');
  await expect(changes).toContainText('settings.ssl_port');
  await expect(changes).toContainText('settings.dtls_port');
  await expect(changes).toContainText('settings.socks_port');
  await expect(changes).toContainText('settings.tpool_log');
  await expect(changes).toContainText('settings.socks.ipver_mixing');
  await expect(changes).toContainText('settings.socks.prefer_ipv6');
  await expect(changes).toContainText('settings.log_level');
  await expect(changes).toContainText('settings.cli.port');
  await expect(changes).toContainText('settings.nameservers');
  await expect(changes).toContainText('settings.udp_quick_ports');
  await expect(changes).toContainText('settings.http_api.allowed_ips');
  await expect(changes).toContainText('settings.http_api.key_timeout');
  await expect(changes).toContainText('settings.http_api.port');
  await expect(changes).toContainText('settings.http_api.key_extend_on_access');
  await expect(changes).toContainText('settings.http_api.bind_address');
  await expect(changes).toContainText('settings.http_api.bind_interface');
  await expect(changes).toContainText('settings.webhook.url');
  await expect(changes).toContainText('settings.webhook.sift_payload_limit_per_direction');
  await expect(changes).toContainText('settings.extended_local_destination_protection');
  await expect(changes).toContainText('settings.webhook.sift_lored_mode');
  await expect(changes).toContainText('settings.webhook.sift_lored_include_url');
  await expect(changes).toContainText('required');
  await expect(changes).toContainText('settings.webhook.sift_url');
  await expect(changes).toContainText('settings.webhook.sift_tenant_id');
  await expect(changes).toContainText('settings.webhook.sift_instance_id');
  await expect(changes).toContainText('settings.webhook.hostid');
  await expect(changes).toContainText('settings.webhook.bind_interface');
  await expect(changes).toContainText('settings.tuning.host_bufsz_min');
  await expect(changes).toContainText('settings.tuning.nbr_cache_size');
  await expect(changes).toContainText('settings.certs_ctlog');
  await expect(changes).toContainText('settings.ca_bundle_file');
  await expect(changes).toContainText('settings.admin.group');
  await expect(changes).toContainText('settings.certs_ca_key_password');
  await expect(changes).toContainText('settings.http_api.keys');
  await expect(changes).toContainText('settings.syslog_server');
  await expect(changes).toContainText('Replaced · redacted');
  await expect(changes).toContainText('Cleared · redacted');
  await expect(changes).toContainText('settings.http_api.allow_api_header');
  await expect(changes).toContainText('debug.log_sockets');
  await expect(changes).toContainText('debug.log.proxy');
  await expect(changes).toContainText('captures.local.format');
  await expect(changes).toContainText('captures.remote.tun_ttl');
  await expect(changes).toContainText('captures.local.dir');
  await expect(changes).toContainText('captures.remote.tun_dst');
  await expect(changes).not.toContainText('hooks.example.test');
  await expect(changes).not.toContainText('new-private-password');
  await expect(changes).not.toContainText('new-api-key');
  await expect(changes).not.toContainText('overlap-api-key');
  await expect(changes).not.toContainText('192.0.2.77');
  await expect(changes).not.toContainText('private-api0');
  await expect(changes).not.toContainText('private-sift.test');
  await expect(changes).not.toContainText('private-tenant');
  await expect(changes).not.toContainText('private-instance');
  await expect(changes).not.toContainText('private-host');
  await expect(changes).not.toContainText('private-webhook0');
  await expect(changes).not.toContainText('ct-log.cnf');
  await expect(changes).not.toContainText('ca-bundle.pem');
  await expect(changes).not.toContainText('private-admins');
  await expect(changes).not.toContainText('/new/private/captures');
});

test('edits nested signature flow metadata with write-only expressions', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'}, true);
  await page.goto('/');
  await page.getByRole('button', {name: 'System', exact: true}).click();
  const trustPosture = page.getByRole('article').filter({
    has: page.getByRole('heading', {name: 'Trust and signatures'}),
  });
  await trustPosture.getByText('Detection signatures', {exact: true}).last().click();
  await trustPosture.getByRole('button', {name: /http\/request · 1 flow step/i}).click();
  const signatureEditor = page.getByRole('dialog', {name: 'Edit http/request'});
  await signatureEditor.getByLabel('Group').fill('web');
  await signatureEditor.getByLabel('Severity').fill('5');
  await signatureEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(page.getByText('Draft: 7 changes')).toBeVisible();

  await signatureEditor.getByRole('button', {name: /1\. R · regex/i}).click();
  const flowEditor = page.getByRole('dialog', {name: 'Edit Flow R'});
  await flowEditor.getByLabel('Byte window').fill('512');
  await flowEditor.getByLabel('Expression', {exact: true}).selectOption('replace');
  await flowEditor.getByLabel('Signature expression replacement').fill('^PRIVATE[0-9]+$');
  await flowEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(page.getByText('Draft: 12 changes')).toBeVisible();
  await expect(flowEditor.getByLabel('Signature expression replacement')).toHaveValue('');
  await expect(flowEditor.getByLabel('Expression', {exact: true})).toHaveValue('unchanged');
  await flowEditor.getByRole('button', {name: 'Cancel'}).click();
  await signatureEditor.getByRole('button', {name: 'Cancel'}).click();

  await page.getByRole('button', {name: 'Review draft · 12'}).click();
  const changes = page.getByRole('table', {name: 'Pending draft changes'});
  await expect(changes).toContainText('detection_signatures.[0].group');
  await expect(changes).toContainText('detection_signatures.[0].severity');
  await expect(changes).toContainText('detection_signatures.[0].flow.[0].signature');
  await expect(changes).toContainText('Replaced · redacted');
  await expect(changes).not.toContainText('PRIVATE');
});

test('rotates nested content rules without exposing expressions', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'}, true);
  await page.goto('/');
  await page.getByRole('button', {name: 'Objects', exact: true}).click();
  const profiles = page.getByRole('group', {name: 'Profiles and routing'});
  await profiles.getByRole('button', {name: /capture content Typed details/i}).click();
  const contentEditor = page.getByRole('dialog', {name: 'Edit capture'});
  await contentEditor.getByRole('group', {name: 'Content rules'})
    .getByRole('button', {name: /Rule 1/}).click();
  const ruleEditor = page.getByRole('dialog', {name: 'Edit Content rule 1'});
  await expect(ruleEditor.getByLabel('Preserve matched length')).toHaveValue('true');
  await ruleEditor.getByLabel('Preserve matched length').selectOption('false');
  await ruleEditor.getByLabel('Replace every Nth match').fill('5');
  await ruleEditor.getByLabel('Match expression').selectOption('replace');
  await ruleEditor.getByLabel('Content match replacement').fill('PRIVATE-MATCH-[0-9]+');
  await ruleEditor.getByLabel('Replacement expression').selectOption('clear');
  await ruleEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(page.getByText('Draft: 4 changes')).toBeVisible();
  await expect(ruleEditor.getByLabel('Content match replacement')).toHaveValue('');
  await ruleEditor.getByRole('button', {name: 'Cancel'}).click();
  await contentEditor.getByRole('button', {name: 'Cancel'}).click();

  await page.getByRole('button', {name: 'Review draft · 4'}).click();
  const changes = page.getByRole('table', {name: 'Pending draft changes'});
  await expect(changes).toContainText('content_profiles.[0].content_rules.[0].match');
  await expect(changes).toContainText('content_profiles.[0].content_rules.[0].replace');
  await expect(changes).toContainText('content_profiles.[0].content_rules.[0].fill_length');
  await expect(changes).toContainText('content_profiles.[0].content_rules.[0].replace_each_nth');
  await expect(changes).toContainText('5');
  await expect(changes).toContainText('Replaced · redacted');
  await expect(changes).toContainText('Cleared · redacted');
  await expect(changes).not.toContainText('PRIVATE-MATCH');
});

test('searches policies and configuration objects without unsafe markup', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'}, true);
  await page.goto('/');
  const search = page.getByRole('searchbox', {name: 'Search'});

  await search.fill('10.0.0.0/24');
  await expect(page.getByRole('heading', {name: 'Search results'})).toBeVisible();
  const results = page.getByRole('group', {name: 'Search results'});
  await expect(results.getByRole('button')).toHaveCount(1);
  await expect(results.getByText('office', {exact: true})).toBeVisible();
  await results.getByRole('button').click();
  await expect(page.getByRole('dialog', {name: 'Edit office'})).toBeVisible();
  await page.keyboard.press('Escape');

  await search.fill('default-ssh');
  await expect(page.getByText('2 matches for “default-ssh”')).toBeVisible();
  await expect(results.getByText('Policy', {exact: true})).toBeVisible();
  await expect(results.getByText('Profile', {exact: true})).toBeVisible();

  await search.fill('<script>');
  await expect(page.getByRole('heading', {name: 'No matches'})).toBeVisible();
  await expect(page.locator('smithproxy-gui script')).toHaveCount(0);
  await page.keyboard.press('Escape');
  await expect(page.getByRole('heading', {name: 'Control plane', level: 2})).toBeVisible();
});

test('declares the Saslik appearance contract and remains usable on mobile', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'});
  await page.setViewportSize({width: 390, height: 844});
  await page.goto('/');

  await expect(page.locator('link[data-saslik-theme]')).toHaveAttribute('href', '/saslik-theme.css');
  await expect(page.locator('script[data-app="smithproxy-gui"]')).toHaveAttribute('src', '/saslik-theme.js');
  const search = page.getByRole('searchbox', {name: 'Search'});
  await expect(search).toBeVisible();
  await search.fill('office-net');
  await expect(page.getByRole('heading', {name: 'Search results'})).toBeVisible();
  await page.keyboard.press('Escape');

  await page.getByRole('button', {name: 'Policy', exact: true}).click();
  await page.getByRole('button', {name: /office office-net/i}).click();
  const editor = page.getByRole('dialog', {name: 'Edit office'});
  await expect(editor).toBeVisible();
  await expect(editor).toHaveCSS('left', '0px');
  await expect.poll(() => editor.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
  await editor.getByRole('button', {name: 'office-net', exact: true}).click();
  await expect(page.getByRole('dialog', {name: 'Edit office-net'})).toHaveCSS('left', '0px');
});

test('derives the system API from a workspace mount', async ({page}) => {
  const requests: string[] = [];
  page.on('request', request => {
    if (request.url().endsWith('/api/v1/status')) requests.push(new URL(request.url()).pathname);
  });
  await mockSystemApi(page, {smithproxy: 'ready'});
  await page.goto('/');
  await page.locator('smithproxy-gui').evaluate(element => element.remove());
  await page.evaluate(() => {
    history.replaceState({}, '', '/ws001/smithproxy-gui/');
    const application = document.createElement('smithproxy-gui');
    application.setAttribute('mode', 'standalone');
    document.body.append(application);
  });

  await expect(page.getByText('Core: Online')).toBeVisible();
  await expect.poll(() => requests).toContain('/ws001/smithproxy-gui/api/v1/status');
});

test.describe('Saslik visual regression', () => {
  for (const theme of Object.keys(saslikVisualThemes) as SaslikVisualTheme[]) {
    test(`${theme} preserves dashboard and nested editor geometry`, async ({page, browserName}) => {
      test.skip(browserName !== 'chromium', 'Canonical pixel baselines use Chromium; behavior runs in every browser.');
      await page.setViewportSize({width: 1440, height: 900});
      await page.emulateMedia({reducedMotion: 'reduce'});
      await page.addInitScript(() => { Date.now = () => 1_800_000_000_000; });
      await mockSystemApi(page, {smithproxy: 'ready', now: 1_800_000_000_000}, true);
      await page.goto('/');
      await expect(page.getByText('Config: Ready')).toBeVisible();
      await applySaslikVisualTheme(page, theme);

      await expect(page).toHaveScreenshot(`${theme}-dashboard.png`, {
        animations: 'disabled', caret: 'hide', maxDiffPixelRatio: 0.001,
      });

      await page.getByRole('button', {name: 'Policy', exact: true}).click();
      await page.getByRole('button', {name: /Policy 1 office internet accept/i}).click();
      await page.getByRole('dialog', {name: 'Edit Policy 1'})
        .getByRole('button', {name: 'office', exact: true}).click();
      await expect(page.getByRole('dialog', {name: 'Edit office'})).toBeVisible();
      await expect(page).toHaveScreenshot(`${theme}-nested-editors.png`, {
        animations: 'disabled', caret: 'hide', maxDiffPixelRatio: 0.001,
      });
    });
  }

  for (const theme of ['petroleum-dark', 'petroleum-light'] as const) {
    test(`${theme} preserves the mobile policy layout`, async ({page, browserName}) => {
      test.skip(browserName !== 'chromium', 'Canonical pixel baselines use Chromium; behavior runs in every browser.');
      await page.setViewportSize({width: 390, height: 844});
      await page.emulateMedia({reducedMotion: 'reduce'});
      await page.addInitScript(() => { Date.now = () => 1_800_000_000_000; });
      await mockSystemApi(page, {smithproxy: 'ready', now: 1_800_000_000_000}, true);
      await page.goto('/');
      await expect(page.getByText('Config: Ready')).toHaveText('Config: Ready');
      await applySaslikVisualTheme(page, theme);
      await page.getByRole('button', {name: 'Policy', exact: true}).click();
      await expect(page.getByRole('heading', {name: 'Policies'})).toBeVisible();
      await expect(page.getByRole('group', {name: 'Policies'}).getByRole('button')).toHaveCount(1);

      await expect(page).toHaveScreenshot(`${theme}-mobile-policy.png`, {
        animations: 'disabled', caret: 'hide', maxDiffPixelRatio: 0.001,
      });
    });
  }
});

test('meets automated WCAG rules across primary and nested views', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'}, true);
  await page.goto('/');
  await expect(page.getByText('Config: Ready')).toBeVisible();
  await expectNoWcagViolations(page);

  await page.getByRole('button', {name: 'Policy', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Policies'})).toBeVisible();
  await expectNoWcagViolations(page);

  await page.getByRole('button', {name: /Policy 1 office internet accept/i}).click();
  const policyEditor = page.getByRole('dialog', {name: 'Edit Policy 1'});
  await expect(policyEditor).toBeVisible();
  await expectNoWcagViolations(page);

  await policyEditor.getByRole('button', {name: 'office', exact: true}).click();
  await expect(page.getByRole('dialog', {name: 'Edit office'})).toBeVisible();
  await expectNoWcagViolations(page);

  await page.setViewportSize({width: 390, height: 844});
  await expect(page.getByRole('dialog', {name: 'Edit office'})).toHaveCSS('left', '0px');
  await expectNoWcagViolations(page);
});
