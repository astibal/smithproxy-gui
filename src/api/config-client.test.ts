import {describe, expect, it, vi} from 'vitest';
import {ApiConfigClient, parseConfigSnapshot} from './config-client';

const liveSnapshot = {
  state: 'ready',
  detail: 'Current runtime configuration',
  checked_at_unix_ms: 100,
  last_success_at_unix_ms: 100,
  view: 'runtime',
  revision: null,
  policies: [{
    id: 'policy-0', name: 'Policy 1', enabled: true, protocol: 'tcp', sources: ['office'],
    source_ports: ['any'], destinations: ['internet'], destination_ports: ['https'],
    features: ['sinkhole'],
    action: 'accept', nat: '', routing: 'main', tls_profile: 'inspect',
    ssh_profile: '', detection_profile: 'default', content_profile: 'capture', auth_profile: '',
    dns_profile: '', script_profile: '',
  }],
  addresses: [
    {id: 'address-0', name: 'office', type: 'cidr', value: '10.0.0.0/24'},
    {id: 'address-1', name: 'internet', type: 'fqdn', value: 'example.test'},
  ],
  ports: [{id: 'port-0', name: 'https', start: 443, end: 443}],
  protocols: [{id: 'protocol-0', name: 'tcp', number: 6}],
  profiles: [
    {
      id: 'tls-0', name: 'inspect', type: 'tls', private_reference_count: 0, routing: null,
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
      id: 'routing-0', name: 'main', type: 'routing', private_reference_count: 0,
      routing: {
        destination_addresses: ['internet'], destination_ports: ['https'],
        load_balancing_method: 'sticky-l3', rewrite_sni: 'old.example', rewrite_sni_to: 'new.example',
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
      id: 'detection-0', name: 'default', type: 'detection', private_reference_count: 2,
      routing: null, tls: null,
      detection: {mode: 2, engines_enabled: true, knowledge_base_enabled: false}, content: null,
      ssh: null, dns: null, script: null, authentication: null,
    },
    {
      id: 'content-0', name: 'capture', type: 'content', private_reference_count: 0,
      routing: null, tls: null, detection: null,
      content: {
        write_payload: false, write_format: 'pcap_single', webhook_enabled: true,
        webhook_locks_traffic: true, ja4_tls_client_hello: true,
        ja4_tls_client_hello_ignores_sni: true, ja4_tls_server_hello: false,
        ja4_http: true, session_filter_configured: true, rule_count: 2,
        rules: [
          {id: 'content-rule-0-0', match_configured: true, replacement_configured: true,
           replacement_has_value: false, fill_length: true, replace_each_nth: 0},
          {id: 'content-rule-0-1', match_configured: true, replacement_configured: true,
           replacement_has_value: true, fill_length: false, replace_each_nth: 3},
        ],
      },
      ssh: null,
      dns: null,
      script: null,
      authentication: null,
    },
  ],
  settings: {
    accept_tproxy: true, accept_redirect: true, accept_socks: false,
    accept_http_connect: true, accept_api: true,
    policy_fail_open: false,
    access_request_fail_open: false,
    workers: {plaintext: 2, tls: 4, udp: 1, dtls: 1, quic: -1, socks: -1, http_connect: 1},
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
      sift_payload_limit_per_direction: 262144, hostid_configured: false,
      bind_interface_configured: false, api_override: false, ping_interval: 120,
      nbr_update_interval: 900, nbr_tag_refresh_age: 300, task_debug: false,
      task_debug_dump: false,
    },
  },
  debug: {
    log_data_crc: false, log_sockets: true, log_online_cx_name: false,
    log_srclines: true, log_srclines_always: false, module_override_count: 1,
    module_overrides: [{name: 'proxy', kind: 'integer', value: 7}],
  },
  captures: {
    local: {
      enabled: true, directory_configured: true, file_prefix_configured: true,
      file_suffix_configured: true, format: 'pcap_single', quota_mib: 512,
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
};

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {status, headers: {'Content-Type': 'application/json'}});
}

describe('ApiConfigClient', () => {
  it('maps the bounded runtime snapshot and derives object impact', async () => {
    const fetcher = vi.fn(async () => response(liveSnapshot));
    const client = new ApiConfigClient('/ws001/smithproxy-gui/api/v1/', fetcher);
    const snapshot = await client.loadSnapshot();

    expect(snapshot).toMatchObject({source: 'live', state: 'ready', revision: null});
    expect(parseConfigSnapshot({
      ...liveSnapshot,
      revision: `sha256:${'a'.repeat(64)}`,
    }).revision).toBe(`sha256:${'a'.repeat(64)}`);
    expect(snapshot.policies[0]).toMatchObject({
      protocol: 'tcp', action: 'accept',
      sources: [{id: 'address-0', name: 'office'}],
    });
    expect(snapshot.addresses[0]?.usedBy).toEqual([
      {id: 'policy-0', kind: 'policy', name: 'Policy 1'},
    ]);
    expect(snapshot.ports[0]).toMatchObject({start: 443, end: 443});
    expect(snapshot.ports[0]?.usedBy).toEqual([
      {id: 'policy-0', kind: 'policy', name: 'Policy 1'},
      {id: 'routing-0', kind: 'routing-profile', name: 'main'},
    ]);
    expect(snapshot.protocols[0]?.usedBy).toEqual([{id: 'policy-0', kind: 'policy', name: 'Policy 1'}]);
    expect(snapshot.profiles.map(item => item.usedBy.length)).toEqual([1, 1, 1, 1]);
    expect(snapshot.profiles[0]?.tls).toMatchObject({
      ocspMode: 1, ocspStaplingMode: 1, redirectWarningPorts: [443, 44443],
      sniBasedCertificates: true, ipBasedCertificates: true,
      failedCertificateOverrideTimeout: 600,
    });
    expect(snapshot.profiles[1]?.routing).toMatchObject({loadBalancingMethod: 'sticky-l3'});
    expect(snapshot.addresses[1]?.usedBy).toContainEqual({id: 'routing-0', kind: 'routing-profile', name: 'main'});
    expect(snapshot.ports[0]?.usedBy).toContainEqual({id: 'routing-0', kind: 'routing-profile', name: 'main'});
    expect(snapshot.profiles[2]?.detection).toMatchObject({mode: 2, knowledgeBaseEnabled: false});
    expect(snapshot.profiles[2]?.privateReferenceCount).toBe(2);
    expect(snapshot.profiles[3]?.content).toMatchObject({
      ruleCount: 2, sessionFilterConfigured: true,
      rules: [
        {fillLength: true, replaceEachNth: 0},
        {fillLength: false, replaceEachNth: 3},
      ],
    });
    expect(snapshot.settings).toMatchObject({
      policyFailOpen: false,
      workers: {tls: 4, quic: -1, socks: -1},
      ports: {tls: 50443, quic: 443},
      ocspStatusTtl: 1800,
      crlStatusTtl: 86400,
      logging: {level: 6, pcapSingleQuota: 100, syslogFamily: 4},
      auxiliary: {cliPort: 50000, socksAsyncDns: true, udpQuickPorts: ['0']},
      nameservers: ['192.0.2.53', '2001:db8::53'],
      httpApi: {
        allowedIps: ['127.0.0.1'], keyTimeout: 3600, port: 55555,
        keyExtendOnAccess: true, bindAddressConfigured: true,
      },
    });
    expect(snapshot.captures).toMatchObject({local: {enabled: true, quotaMiB: 512}});
    expect(snapshot.securityAssets).toMatchObject({
      certificateAuthorityCount: 1, starttlsSignatureCount: 1, detectionFlowStepCount: 1,
      certificateAuthorities: [{id: 'certificate-authority-0', name: 'default', pathConfigured: true}],
      signatures: [{id: 'starttls-signature-0'}, {id: 'detection-signature-0'}],
    });
    const augmented = parseConfigSnapshot({
      ...liveSnapshot,
      augment_support: true,
      value_origins: [{
        path: 'policy.[0].action', persistent_value: 'reject', effective_value: 'accept',
        layers: [
          {id: 'temporary-office-access', priority: 50, value: 'reject', active: false},
          {id: 'incident-response', priority: 100, value: 'accept', active: true},
        ], editable: false,
      }, {
        path: 'policy.[0].src', persistent_value: ['office-net'], effective_value: ['maintenance-net'],
        layers: [
          {id: 'expanded-office', priority: 50, value: ['office-net', 'guest-net'], active: false},
          {id: 'maintenance-only', priority: 100, value: ['maintenance-net'], active: true},
        ], editable: false,
      }, {
        path: 'policy.[0].sport', persistent_value: [], effective_value: ['https'],
        layers: [
          {id: 'default-source-ports', priority: 10, value: [], active: false},
          {id: 'restricted-source-ports', priority: 20, value: ['https'], active: true},
        ], editable: false,
      }],
    });
    expect(augmented.valueOrigins[0]).toMatchObject({
      path: 'policy.[0].action', persistentValue: 'reject', effectiveValue: 'accept',
      layers: [
        {id: 'temporary-office-access', priority: 50, value: 'reject', active: false},
        {id: 'incident-response', priority: 100, value: 'accept', active: true},
      ],
    });
    expect(augmented.valueOrigins[1]).toMatchObject({
      path: 'policy.[0].src', persistentValue: ['office-net'], effectiveValue: ['maintenance-net'],
      layers: [
        {id: 'expanded-office', value: ['office-net', 'guest-net'], active: false},
        {id: 'maintenance-only', value: ['maintenance-net'], active: true},
      ],
    });
    expect(augmented.valueOrigins[2]).toMatchObject({
      path: 'policy.[0].sport', persistentValue: [], effectiveValue: ['https'],
    });
    expect(fetcher).toHaveBeenCalledWith(
      '/ws001/smithproxy-gui/api/v1/config/snapshot',
      expect.objectContaining({cache: 'no-store', credentials: 'same-origin', redirect: 'error'}),
    );
  });

  it('rejects malformed collections, unsafe paths, and non-success responses', async () => {
    expect(() => new ApiConfigClient('https://other.example/api')).toThrow('same-origin');
    expect(() => new ApiConfigClient('/api/../secret')).toThrow('relative path');
    expect(() => parseConfigSnapshot({...liveSnapshot, addresses: [
      liveSnapshot.addresses[0], {...liveSnapshot.addresses[0], id: 'address-2'},
    ]})).toThrow('Duplicate address object');
    expect(() => parseConfigSnapshot({...liveSnapshot, addresses: [
      {...liveSnapshot.addresses[0], type: 'subnet'},
    ]})).toThrow('Invalid address type');
    expect(() => parseConfigSnapshot({...liveSnapshot, ports: [
      {id: 'bad', name: 'bad', start: 10, end: 1},
    ]})).toThrow('Invalid port range');
    expect(() => parseConfigSnapshot({...liveSnapshot, protocols: [
      {id: 'reserved', name: 'reserved', number: 0},
    ]})).toThrow('Invalid protocol number');
    expect(() => parseConfigSnapshot({...liveSnapshot, state: {toString: () => 'ready'}}))
      .toThrow('Invalid configuration snapshot');
    expect(() => parseConfigSnapshot({...liveSnapshot, revision: 'revision-7'}))
      .toThrow('Invalid configuration snapshot');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot,
      profiles: liveSnapshot.profiles.map(profile => profile.type === 'content'
        ? {...profile, content: {...profile.content, rule_count: 3}}
        : profile),
    })).toThrow('Invalid content rule count');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot,
      profiles: liveSnapshot.profiles.map(profile => profile.type === 'content'
        ? {...profile, content: {
            ...profile.content,
            rules: profile.content!.rules.map(rule => ({...rule, replace_each_nth: 2147483648})),
          }}
        : profile),
    })).toThrow('Invalid content rule replacement interval');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot,
      profiles: liveSnapshot.profiles.map(profile => profile.type === 'tls'
        ? {...profile, tls: {...profile.tls, redirect_warning_ports: [443, 443]}}
        : profile),
    })).toThrow('Duplicate TLS redirect warning port');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot,
      security_assets: {
        ...liveSnapshot.security_assets,
        certificate_authority_count: 0,
        certificate_authority_path_count: 1,
      },
    })).toThrow('Invalid certificate authority posture');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot,
      security_assets: {
        ...liveSnapshot.security_assets,
        detection_flow_step_count: 2,
      },
    })).toThrow('Invalid signature posture');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot, augment_support: false,
      value_origins: [{
        path: 'policy.[0].action', persistent_value: 'reject', effective_value: 'accept',
        layers: [{id: 'unexpected', priority: null, value: 'accept', active: true}], editable: false,
      }],
    })).toThrow('Unexpected provenance without augment support');
    for (const path of [
      'settings.http_api.keys',
      'tls_profiles.[0].sni_filter_bypass',
      'content_profiles.[0].rules_session_filter',
      'policy.[0].future_secret',
    ]) {
      expect(() => parseConfigSnapshot({
        ...liveSnapshot, augment_support: true,
        value_origins: [{
          path, persistent_value: 'redacted', effective_value: 'redacted',
          layers: [{id: 'unsafe-origin', priority: null, value: 'redacted', active: true}],
          editable: false,
        }],
      })).toThrow('Invalid value provenance entry');
    }
    expect(() => parseConfigSnapshot({
      ...liveSnapshot, augment_support: true,
      value_origins: [{
        path: 'policy.[0].action', persistent_value: 'reject', effective_value: 'accept',
        layers: [
          {id: 'incorrect-owner', priority: 200, value: 'reject', active: true},
          {id: 'later-layer', priority: 100, value: 'accept', active: false},
        ], editable: false,
      }],
    })).toThrow('Active augment layer must terminate the chain');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot, augment_support: true,
      value_origins: [{
        path: 'policy.[0].action', persistent_value: 'reject', effective_value: 'accept',
        layers: [{id: 'wrong-value', priority: null, value: 'reject', active: true}], editable: false,
      }],
    })).toThrow('Invalid active augment layer');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot, augment_support: true,
      value_origins: [{
        path: 'policy.[0].src', persistent_value: ['office-net'], effective_value: ['guest-net'],
        layers: [{id: 'mixed-list', priority: null, value: ['guest-net', 42], active: true}],
        editable: false,
      }],
    })).toThrow('Invalid augment layer value');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot, augment_support: true,
      value_origins: [{
        path: 'policy.[0].src', persistent_value: ['office-net'], effective_value: [443],
        layers: [{id: 'wrong-list-type', priority: null, value: [443], active: true}],
        editable: false,
      }],
    })).toThrow('Inconsistent augment layer value types');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot, augment_support: true,
      value_origins: [{
        path: 'policy.[0].src', persistent_value: ['office-net'], effective_value: ['guest-net'],
        layers: [{id: 'wrong-list-value', priority: null, value: ['office-net'], active: true}],
        editable: false,
      }],
    })).toThrow('Invalid active augment layer');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot, augment_support: true,
      value_origins: [{
        path: 'policy.[0].src', persistent_value: ['office-net'], effective_value: ['guest-net'],
        layers: [{
          id: 'oversized-list', priority: null,
          value: Array.from({length: 257}, (_, index) => `object-${index}`), active: true,
        }],
        editable: false,
      }],
    })).toThrow('Invalid augment layer value');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot, augment_support: true,
      value_origins: [{
        path: 'policy.[0].action', persistent_value: 'reject', effective_value: 'accept',
        layers: [
          {id: 'priority-200', priority: 200, value: 'reject', active: false},
          {id: 'priority-100', priority: 100, value: 'accept', active: true},
        ], editable: false,
      }],
    })).toThrow('strictly increasing');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot, augment_support: true,
      value_origins: [{
        path: 'policy.[0].action', persistent_value: 'reject', effective_value: 'accept',
        layers: [
          {id: 'ordered-layer', priority: null, value: 'reject', active: false},
          {id: 'priority-100', priority: 100, value: 'accept', active: true},
        ], editable: false,
      }],
    })).toThrow('Inconsistent augment layer priorities');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot, augment_support: true,
      value_origins: [{
        path: 'policy.[0].action', persistent_value: 'reject', effective_value: 'accept',
        layers: [{id: 'unsafe layer', priority: null, value: 'accept', active: true}], editable: false,
      }],
    })).toThrow('Invalid augment layer');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot,
      debug: {...liveSnapshot.debug, module_override_count: 2},
    })).toThrow('Invalid debug module override count');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot,
      settings: {
        ...liveSnapshot.settings,
        http_api: {...liveSnapshot.settings.http_api, port: 1024},
      },
    })).toThrow('Invalid API port');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot,
      debug: {
        ...liveSnapshot.debug,
        module_override_count: 2,
        module_overrides: [
          {name: 'proxy', kind: 'integer', value: 7},
          {name: 'proxy', kind: 'boolean', value: false},
        ],
      },
    })).toThrow('Invalid debug module name');

    const client = new ApiConfigClient('/api/v1', async () => response({}, 401));
    await expect(client.loadSnapshot()).rejects.toThrow('HTTP 401');

    const oversized = new ApiConfigClient('/api/v1', async () => new Response('{}', {
      headers: {'Content-Length': String(4 * 1024 * 1024 + 1)},
    }));
    await expect(oversized.loadSnapshot()).rejects.toThrow('size limit');
  });

  it('cancels an in-flight privileged snapshot request', async () => {
    let signal: AbortSignal | undefined;
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      signal = init?.signal ?? undefined;
      return new Promise<Response>((_resolve, reject) => {
        signal?.addEventListener('abort', () => reject(new Error('request cancelled')), {once: true});
      });
    });
    const client = new ApiConfigClient('/api/v1', fetcher);
    const pending = client.loadSnapshot();

    client.cancelPendingRequests();

    expect(signal?.aborted).toBe(true);
    await expect(pending).rejects.toThrow('request cancelled');
  });
});
