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
      id: 'detection-0', name: 'default', type: 'detection', routing: null, tls: null,
      detection: {mode: 2, engines_enabled: true, knowledge_base_enabled: false}, content: null,
      ssh: null, dns: null, script: null, authentication: null,
    },
    {
      id: 'content-0', name: 'capture', type: 'content', routing: null, tls: null, detection: null,
      content: {
        write_payload: false, write_format: 'pcap_single', webhook_enabled: true,
        webhook_locks_traffic: true, ja4_tls_client_hello: true,
        ja4_tls_client_hello_ignores_sni: true, ja4_tls_server_hello: false,
        ja4_http: true, session_filter_configured: true, rule_count: 2,
      },
      ssh: null,
      dns: null,
      script: null,
      authentication: null,
    },
  ],
  settings: {
    accept_tproxy: true, accept_redirect: true, accept_socks: false,
    accept_http_connect: true, accept_api: true, policy_fail_open: false,
    access_request_fail_open: false,
    workers: {plaintext: 2, tls: 4, udp: 1, dtls: 1, quic: -1, socks: -1, http_connect: 1},
    ports: {plaintext: 50080, tls: 50443, udp: 50080, quic: 443, http_connect: 3128},
    ocsp_status_ttl: 1800, crl_status_ttl: 86400,
    logging: {
      default_write_payload: false, payload_directory_configured: true, pcap_single_quota: 100,
      level: 6, file_configured: true, console: true, ssl_key_file_configured: true,
      syslog_server_configured: false, syslog_port: 514, syslog_facility: 23,
      syslog_level: 6, syslog_family: 4,
    },
    auxiliary: {
      udp_quick_port_count: 1, udp_quick_ports: ['0'], certificates_path_configured: true,
      certificate_password_configured: true, ca_bundle_path_configured: true,
      messages_directory_configured: true, payload_file_prefix_configured: false,
      payload_file_suffix_configured: false, cli_port: 50000, cli_password_configured: false,
      web_rating_key_configured: false, socks_async_dns: true,
    },
    tls_autodetect: true, tls_autodetect_harder: false, kernel_tls: false,
    nameserver_count: 2, nameservers: ['192.0.2.53', '2001:db8::53'],
    http_api: {
      key_count: 1, allowed_ip_count: 1, allowed_ips: ['127.0.0.1'],
      loopback_only: true, pam_login: false, allow_api_header: false,
    },
    webhook: {enabled: false, tls_verify: true, url_configured: false, sift_enabled: false, api_override: false},
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
        side: 'client', group: '', enables: '', engine: '',
        flow: [
          {id: 'starttls-signature-0-flow-0', side: 'r', type: 'regex', expression_configured: true,
           bytes_start: 0, bytes_max: 16},
          {id: 'starttls-signature-0-flow-1', side: 'w', type: 'regex', expression_configured: true,
           bytes_start: 0, bytes_max: 512},
        ],
      },
      {
        id: 'detection-signature-0', kind: 'detection', category: 'www', name: 'http/request',
        side: 'client', group: 'base', enables: 'http', engine: 'http1',
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
    expect(snapshot.profiles[1]?.routing).toMatchObject({loadBalancingMethod: 'sticky-l3'});
    expect(snapshot.addresses[1]?.usedBy).toContainEqual({id: 'routing-0', kind: 'routing-profile', name: 'main'});
    expect(snapshot.ports[0]?.usedBy).toContainEqual({id: 'routing-0', kind: 'routing-profile', name: 'main'});
    expect(snapshot.profiles[2]?.detection).toMatchObject({mode: 2, knowledgeBaseEnabled: false});
    expect(snapshot.profiles[3]?.content).toMatchObject({ruleCount: 2, sessionFilterConfigured: true});
    expect(snapshot.settings).toMatchObject({
      policyFailOpen: false,
      workers: {tls: 4, quic: -1, socks: -1},
      ports: {tls: 50443, quic: 443},
      ocspStatusTtl: 1800,
      crlStatusTtl: 86400,
      logging: {level: 6, pcapSingleQuota: 100, syslogFamily: 4},
      auxiliary: {cliPort: 50000, socksAsyncDns: true, udpQuickPorts: ['0']},
      nameservers: ['192.0.2.53', '2001:db8::53'],
      httpApi: {allowedIps: ['127.0.0.1']},
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
        layers: [{id: 'temporary-office-access', priority: 100}], editable: false,
      }],
    });
    expect(augmented.valueOrigins[0]).toMatchObject({
      path: 'policy.[0].action', persistentValue: 'reject', effectiveValue: 'accept',
      layers: [{id: 'temporary-office-access', priority: 100}],
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
    expect(() => parseConfigSnapshot({...liveSnapshot, ports: [
      {id: 'bad', name: 'bad', start: 10, end: 1},
    ]})).toThrow('Invalid port range');
    expect(() => parseConfigSnapshot({...liveSnapshot, state: {toString: () => 'ready'}}))
      .toThrow('Invalid configuration snapshot');
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
        layers: [{id: 'unexpected', priority: null}], editable: false,
      }],
    })).toThrow('Unexpected provenance without augment support');
    expect(() => parseConfigSnapshot({
      ...liveSnapshot,
      debug: {...liveSnapshot.debug, module_override_count: 2},
    })).toThrow('Invalid debug module override count');
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
});
