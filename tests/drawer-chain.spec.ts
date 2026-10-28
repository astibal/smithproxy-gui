import {expect, test, type Page} from '@playwright/test';

type MockState = {smithproxy: 'ready' | 'unreachable'};

async function mockSystemApi(page: Page, state: MockState, configRead = false): Promise<void> {
  let draft = {id: 'workspace-draft', base_revision: null, version: 0, changes: [] as Array<{path: string; value: unknown}>};
  await page.route('**/api/v1/capabilities', async route => route.fulfill({json: {
    service: 'smithproxy-gui',
    api_version: 'v1',
    base_path: '/',
    smithproxy_state: state.smithproxy,
    features: {
      config_read: configRead, config_write: false, drafts: configRead, jobs: false, events: true,
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
      checked_at_unix_ms: Date.now(),
      last_success_at_unix_ms: Date.now() - 5000,
      latency_ms: state.smithproxy === 'ready' ? 12 : 2500,
      total_probes: 3,
      consecutive_failures: state.smithproxy === 'ready' ? 0 : 1,
      availability_window: {samples: 2, successful: state.smithproxy === 'ready' ? 2 : 1},
      history: state.smithproxy === 'ready'
        ? [
            {state: 'ready', checked_at_unix_ms: Date.now() - 5000, latency_ms: 11},
            {state: 'ready', checked_at_unix_ms: Date.now(), latency_ms: 12},
          ]
        : [
            {state: 'ready', checked_at_unix_ms: Date.now() - 5000, latency_ms: 11},
            {state: 'unreachable', checked_at_unix_ms: Date.now(), latency_ms: 2500},
          ],
    },
  }}));
  await page.route('**/api/v1/metrics/summary', async route => route.fulfill({json: {
    state: state.smithproxy === 'ready' ? 'ready' : 'unavailable',
    detail: state.smithproxy === 'ready' ? 'Current listener metrics' : 'Metrics are stale',
    checked_at_unix_ms: Date.now(),
    last_success_at_unix_ms: Date.now() - 5000,
    totals: {workers: 3, sessions_total: 19, sessions_active: 4, bytes_up: 1536, bytes_down: 2304},
    listeners: [
      {name: 'tcp', workers: 2, sessions_total: 12, sessions_active: 3, bytes_up: 1024, bytes_down: 2048},
      {name: 'tls', workers: 1, sessions_total: 7, sessions_active: 1, bytes_up: 512, bytes_down: 256},
    ],
  }}));
  await page.route('**/api/v1/sessions/activity', async route => route.fulfill({json: {
    state: state.smithproxy === 'ready' ? 'ready' : 'unavailable',
    detail: state.smithproxy === 'ready' ? 'Current session activity' : 'Session activity is stale',
    checked_at_unix_ms: Date.now(),
    last_success_at_unix_ms: Date.now() - 5000,
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
    checked_at_unix_ms: Date.now(), last_success_at_unix_ms: Date.now() - 5000,
    size: 42, capacity: 1000,
  }}));
  await page.route('**/api/v1/network/neighbors/summary', async route => route.fulfill({json: {
    state: state.smithproxy === 'ready' ? 'ready' : 'unavailable',
    detail: state.smithproxy === 'ready' ? 'Current neighborhood aggregates' : 'Neighborhood is stale',
    checked_at_unix_ms: Date.now(), last_success_at_unix_ms: Date.now() - 5000,
    hosts_total: 8, active_today: 3, active_week: 6, tagged_hosts: 4,
    observations: 20, bytes_up: 1000, bytes_down: 2000,
  }}));
  await page.route('**/api/v1/events/recent', async route => route.fulfill({json: {
    source: 'gui-core', smithproxy_events_available: false,
    events: [
      {
        id: '0-100', occurred_at_unix_ms: Date.now() - 5000, severity: 'info',
        source: 'gui-core', message: 'Smithproxy control plane is reachable',
      },
      ...(state.smithproxy === 'ready' ? [] : [{
        id: '1-200', occurred_at_unix_ms: Date.now(), severity: 'error',
        source: 'gui-core', message: 'Smithproxy control plane changed to unreachable',
      }]),
    ],
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
    await page.route('**/api/v1/config/snapshot', async route => route.fulfill({json: {
      state: 'ready', detail: 'Current runtime configuration', checked_at_unix_ms: Date.now(),
      last_success_at_unix_ms: Date.now(), view: 'runtime', revision: null,
      policies: [{
        id: 'policy-0', name: 'Policy 1', enabled: true, protocol: 'tcp', sources: ['office'],
        source_ports: ['any'], destinations: ['internet'], destination_ports: ['https'],
        features: ['sinkhole'],
        action: 'accept', nat: '', routing: 'main', tls_profile: 'inspect',
        ssh_profile: '', detection_profile: 'detect', content_profile: '', auth_profile: '',
        dns_profile: 'resolver', script_profile: '',
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
            inspect: true, allow_untrusted_issuers: false, allow_invalid_certificates: false,
            allow_self_signed: false, certificate_transparency: true, ocsp_stapling: true,
            block_alpn: false, only_custom_certificates: false, no_fallback_bypass: true,
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
      ],
      settings: {
        accept_tproxy: true, accept_redirect: true, accept_socks: false,
        accept_http_connect: true, accept_api: true, policy_fail_open: false,
        access_request_fail_open: false,
        workers: {plaintext: 2, tls: 4, udp: 1, dtls: 1, quic: 0, socks: 0, http_connect: 1},
        tls_autodetect: true, tls_autodetect_harder: false, kernel_tls: false,
        nameserver_count: 2,
        http_api: {key_count: 1, allowed_ip_count: 1, loopback_only: true, pam_login: false, allow_api_header: false},
        webhook: {enabled: false, tls_verify: true, url_configured: false, sift_enabled: false, api_override: false},
      },
      captures: {
        local: {enabled: false, directory_configured: true, format: 'pcap_single', quota_mib: 1024},
        remote: {
          enabled: false, tunnel_type: 'gre', gre_format: 'traffic',
          destination_configured: false, ttl: 1, bind_interface_configured: false,
        },
        calculate_checksums: true,
      },
      security_assets: {
        certificate_authority_count: 1, certificate_authority_path_count: 1,
        starttls_signature_count: 6, starttls_flow_step_count: 12,
        detection_signature_count: 24, detection_flow_step_count: 31,
      },
      augment_support: false,
      value_origins: [],
    }}));
  }
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
  const action = editor.getByLabel('Action');
  await action.fill('reject');
  await editor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(editor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 4 changes')).toBeVisible();
  await expect(page.getByText('Config: Ready')).toBeVisible();
  await editor.getByRole('button', {name: 'tcp', exact: true}).click();
  const protocolEditor = page.getByRole('dialog', {name: 'Edit tcp'});
  await expect(protocolEditor).toBeVisible();
  await protocolEditor.getByLabel('IP protocol number').fill('17');
  await protocolEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(protocolEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 6 changes')).toBeVisible();
  await protocolEditor.getByRole('button', {name: 'Cancel'}).click();
  await editor.getByRole('button', {name: 'https', exact: true}).click();
  const portEditor = page.getByRole('dialog', {name: 'Edit https'});
  await expect(portEditor).toBeVisible();
  await portEditor.getByLabel('Start').fill('9000');
  await portEditor.getByLabel('End').fill('8000');
  await portEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(portEditor.getByText(/valid port range from 0 to 65535/i)).toBeVisible();
  await expect(page.getByText('Draft: 6 changes')).toBeVisible();
  await portEditor.getByLabel('Start').fill('8443');
  await portEditor.getByLabel('End').fill('8443');
  await portEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(portEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 9 changes')).toBeVisible();
  await portEditor.getByRole('button', {name: 'Cancel'}).click();
  await editor.getByRole('button', {name: 'inspect', exact: true}).click();
  const tlsEditor = page.getByRole('dialog', {name: 'Edit inspect'});
  await expect(tlsEditor).toBeVisible();
  await expect(tlsEditor.getByText('Strict')).toBeVisible();
  await expect(tlsEditor.getByText('2 redacted entries')).toBeVisible();
  await expect(tlsEditor.getByText(/SNI bypass values stay inside the GUI core/i)).toBeVisible();
  await page.keyboard.press('Escape');
  await editor.getByRole('button', {name: 'detect', exact: true}).click();
  const detectionEditor = page.getByRole('dialog', {name: 'Edit detect'});
  await detectionEditor.getByLabel('Detection phase').selectOption('2');
  await detectionEditor.getByLabel('L7 engines').selectOption('false');
  await detectionEditor.getByLabel('Knowledge base').selectOption('true');
  await detectionEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(detectionEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 13 changes')).toBeVisible();
  await detectionEditor.getByRole('button', {name: 'Cancel'}).click();
  await editor.getByRole('button', {name: 'resolver', exact: true}).click();
  const dnsEditor = page.getByRole('dialog', {name: 'Edit resolver'});
  await dnsEditor.getByLabel('Match request ID').selectOption('false');
  await dnsEditor.getByLabel('Randomize upstream ID').selectOption('false');
  await dnsEditor.getByLabel('Cached responses').selectOption('true');
  await dnsEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(dnsEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 17 changes')).toBeVisible();
  await dnsEditor.getByRole('button', {name: 'Cancel'}).click();
  await editor.getByRole('button', {name: 'main', exact: true}).click();
  const routingEditor = page.getByRole('dialog', {name: 'Edit main'});
  await routingEditor.getByLabel('Destination addresses').fill('internet, office');
  await routingEditor.getByLabel('Load balancing').selectOption('sticky-l4');
  await routingEditor.getByLabel('Rewrite SNI match').fill('old.example');
  await routingEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(routingEditor.getByText(/SNI rewrite requires both values/i)).toBeVisible();
  await expect(page.getByText('Draft: 17 changes')).toBeVisible();
  await routingEditor.getByLabel('Rewrite SNI target').fill('new.example');
  await routingEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(routingEditor.getByText('Saved to draft')).toBeVisible();
  await expect(page.getByText('Draft: 23 changes')).toBeVisible();
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
  await expect(page.getByText('Draft: 26 changes')).toBeVisible();
  await addressEditor.getByRole('button', {name: 'Cancel'}).click();
  await expect(addressEditor).not.toBeVisible();
  await editor.getByRole('button', {name: 'Cancel'}).click();
  await expect(editor).not.toBeVisible();
  await page.getByRole('button', {name: 'Review draft · 26'}).click();
  await expect(page.getByRole('heading', {name: 'Workspace draft'})).toBeVisible();
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('address_objects.[0].value');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('10.0.1.0/24');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('routing.[0].dnat_lb_method');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('sticky-l4');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('detection_profiles.[0].mode');
  await expect(page.getByRole('table', {name: 'Pending draft changes'})).toContainText('alg_dns_profiles.[0].cached_responses');
  await page.getByRole('button', {name: 'Discard draft'}).click();
  await expect(page.getByRole('button', {name: 'Confirm discard 26 changes'})).toBeVisible();
  await expect(page.getByText('Draft: 26 changes')).toBeVisible();
  await page.getByRole('button', {name: 'Confirm discard 26 changes'}).click();
  await expect(page.getByText('Draft: 0 changes')).toBeVisible();
  await expect(page.getByText('No pending changes')).toBeVisible();
});

test('opens a policy and its referenced address object', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'});
  await page.goto('/');
  await page.getByRole('button', {name: 'Policy', exact: true}).click();
  await page.getByRole('button', {name: /office office-net/i}).click();
  await expect(page.getByRole('dialog', {name: 'Edit office'})).toBeVisible();
  await expect(page.getByText(/temporary-office-access \(priority 100\)/i)).toBeVisible();
  await expect(page.locator('.origin-note')).toContainText('Effective accept overrides persistent reject');

  await page.getByRole('button', {name: 'office-net', exact: true}).click();
  const addressEditor = page.getByRole('dialog', {name: 'Edit office-net'});
  await expect(addressEditor).toBeVisible();
  await expect(page.getByText('This shared object is used by 4 configuration entries.')).toBeVisible();

  await addressEditor.getByRole('button', {name: 'Save to draft'}).click();
  await expect(page.getByText('Draft: 1 changes')).toBeVisible();

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

  const reference = page.getByRole('button', {name: 'office-net', exact: true});
  await reference.click();
  await expect(page.locator('#address-name-address-office-net')).toBeFocused();
  await expect.poll(() => new URL(page.url()).searchParams.get('edit')).toBe(
    'policy:policy-office,address:address-office-net',
  );

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

test('shows live Smithproxy status transitions', async ({page}) => {
  const state: MockState = {smithproxy: 'ready'};
  await mockSystemApi(page, state);
  await page.goto('/');

  await expect(page.getByText('Core: Online')).toBeVisible();
  await expect(page.getByText('Smithproxy: Ready')).toBeVisible();
  await expect(page.getByText('12 ms')).toBeVisible();
  await expect(page.getByRole('region', {name: 'Probe history'})).toBeVisible();
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

  state.smithproxy = 'unreachable';
  await page.evaluate(() => window.dispatchEvent(new Event('online')));
  await expect(page.getByText('Smithproxy: Unreachable')).toBeVisible();

  state.smithproxy = 'ready';
  await page.evaluate(() => window.dispatchEvent(new Event('online')));
  await expect(page.getByText('Smithproxy: Ready')).toBeVisible();
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
  await expect(contentEditor.getByText('2 redacted rules')).toBeVisible();
  await expect(contentEditor.getByText(/patterns, replacements, and session filters stay inside/i)).toBeVisible();
  await page.keyboard.press('Escape');
  await profiles.getByRole('button', {name: /default-ssh ssh Typed details/i}).click();
  const sshEditor = page.getByRole('dialog', {name: 'Edit default-ssh'});
  await expect(sshEditor.getByText('Configured · path redacted')).toBeVisible();
  await expect(sshEditor.getByText('strict')).toBeVisible();
  await page.keyboard.press('Escape');
  await profiles.getByRole('button', {name: /safe-dns dns Typed details/i}).click();
  await expect(page.getByRole('dialog', {name: 'Edit safe-dns'}).getByText('Randomize upstream ID')).toBeVisible();
  await page.keyboard.press('Escape');
  await profiles.getByRole('button', {name: /audit script Typed details/i}).click();
  const scriptEditor = page.getByRole('dialog', {name: 'Edit audit'});
  await expect(scriptEditor.getByText('Configured · path redacted')).toBeVisible();
  await page.keyboard.press('Escape');
  await profiles.getByRole('button', {name: /legacy-auth authentication Typed details/i}).click();
  const authenticationEditor = page.getByRole('dialog', {name: 'Edit legacy-auth'});
  await expect(authenticationEditor.getByText('Deprecated compatibility profile')).toBeVisible();
  await expect(authenticationEditor.getByText('2 redacted entries')).toBeVisible();
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
  await expect(trustPosture.getByText('24', {exact: true})).toBeVisible();
  await expect(trustPosture.getByText(/paths and signature expressions are redacted/i)).toBeVisible();
});

test('declares the Saslik appearance contract and remains usable on mobile', async ({page}) => {
  await mockSystemApi(page, {smithproxy: 'ready'});
  await page.setViewportSize({width: 390, height: 844});
  await page.goto('/');

  await expect(page.locator('link[data-saslik-theme]')).toHaveAttribute('href', '/saslik-theme.css');
  await expect(page.locator('script[data-app="smithproxy-gui"]')).toHaveAttribute('src', '/saslik-theme.js');
  await page.getByRole('button', {name: 'Objects', exact: true}).click();
  await page.getByRole('button', {name: /office-net subnet/i}).click();
  const editor = page.getByRole('dialog', {name: 'Edit office-net'});
  await expect(editor).toBeVisible();
  await expect(editor).toHaveCSS('left', '0px');
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
