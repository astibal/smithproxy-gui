import type {
  AddressObject,
  CaptureSettings,
  DebugSettings,
  SecurityAssets,
  ConfigClient,
  ConfigReference,
  ConfigSnapshot,
  ConfigUsage,
  PolicySummary,
  PortObject,
  ProfileObject,
  ProtocolObject,
  SystemSettings,
  ValueOrigin,
} from './models';

type JsonObject = Record<string, unknown>;
type Usage = ConfigUsage;
type MutableAddress = Omit<AddressObject, 'usedBy'> & {usedBy: Usage[]};
type MutablePort = Omit<PortObject, 'usedBy'> & {usedBy: Usage[]};
type MutableProtocol = Omit<ProtocolObject, 'usedBy'> & {usedBy: Usage[]};
type MutableProfile = Omit<ProfileObject, 'usedBy'> & {usedBy: Usage[]};

const MAX_POLICIES = 4096;
const MAX_OBJECTS = 4096;
const MAX_REFERENCES = 256;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function configScalar(value: unknown, label: string): boolean | number | string {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  if (typeof value === 'string' && value.length <= 1024 && !/[\u0000-\u001f\u007f]/u.test(value)) return value;
  throw new Error(`Invalid ${label}.`);
}

function safeString(value: unknown, label: string, maximum = 1024): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`Invalid ${label}.`);
  }
  return value;
}

function optionalString(value: unknown, label: string, maximum = 128): string {
  if (typeof value !== 'string' || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`Invalid ${label}.`);
  }
  return value;
}

function safeInteger(value: unknown, label: string, maximum: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new Error(`Invalid ${label}.`);
  }
  return value;
}

function safeBoolean(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') throw new Error(`Invalid ${label}.`);
  return value;
}

function nullableInteger(value: unknown, label: string): number | null {
  return value === null ? null : safeInteger(value, label, Number.MAX_SAFE_INTEGER);
}

function boundedArray(value: unknown, label: string, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) throw new Error(`Invalid ${label}.`);
  return value;
}

function stringArray(value: unknown, label: string): string[] {
  return boundedArray(value, label, MAX_REFERENCES).map(item => safeString(item, label, 128));
}

function normalizedPath(value: string): string {
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\') || /[?#]/u.test(value)) {
    throw new Error('API base must be a same-origin absolute path.');
  }
  const segments = value.split('/').filter(Boolean);
  if (segments.some(segment => segment === '.' || segment === '..')) {
    throw new Error('API base cannot contain relative path segments.');
  }
  return segments.length === 0 ? '/' : `/${segments.join('/')}`;
}

async function boundedJson(response: Response): Promise<unknown> {
  const declaredLength = response.headers.get('Content-Length');
  if (declaredLength !== null && (!/^\d+$/u.test(declaredLength) || Number(declaredLength) > MAX_RESPONSE_BYTES)) {
    throw new Error('Configuration response exceeded the size limit.');
  }
  if (!response.body) return JSON.parse(await response.text()) as unknown;

  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', {fatal: true});
  let size = 0;
  let text = '';
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('Configuration response exceeded the size limit.');
      }
      text += decoder.decode(value, {stream: true});
    }
    text += decoder.decode();
    return JSON.parse(text) as unknown;
  } catch (error) {
    if (error instanceof Error && error.message.includes('size limit')) throw error;
    throw new Error('Configuration API returned invalid JSON.');
  } finally {
    reader.releaseLock();
  }
}

function parseAddress(value: unknown): MutableAddress {
  if (!isObject(value)) throw new Error('Invalid address object.');
  const type = safeString(value.type, 'address type', 16);
  if (type !== 'cidr' && type !== 'fqdn') throw new Error('Invalid address type.');
  return {
    id: safeString(value.id, 'address ID', 128),
    name: safeString(value.name, 'address name', 128),
    type,
    value: safeString(value.value, 'address value'),
    usedBy: [],
  };
}

function references(values: string[], addresses: ReadonlyMap<string, AddressObject>): ConfigReference[] {
  return values.map(name => ({id: addresses.get(name)?.id ?? null, name}));
}

export function parseConfigSnapshot(value: unknown): ConfigSnapshot {
  if (!isObject(value) || typeof value.state !== 'string' ||
      !['ready', 'starting', 'unavailable', 'unconfigured'].includes(value.state) ||
      typeof value.detail !== 'string' || value.detail.length > 1024 ||
      /[\u0000-\u001f\u007f]/u.test(value.detail) || value.view !== 'runtime' ||
      !(value.revision === null || (typeof value.revision === 'string' && value.revision.length <= 128))) {
    throw new Error('Invalid configuration snapshot.');
  }

  const addressValues = boundedArray(value.addresses, 'address collection', MAX_OBJECTS);
  const addresses = addressValues.map(parseAddress);
  const addressNames = new Map<string, MutableAddress>();
  const addressesById = new Map<string, MutableAddress>();
  const addressIds = new Set<string>();
  for (const address of addresses) {
    if (addressNames.has(address.name) || addressIds.has(address.id)) throw new Error('Duplicate address object.');
    addressNames.set(address.name, address);
    addressIds.add(address.id);
    addressesById.set(address.id, address);
  }

  const policies = boundedArray(value.policies, 'policy collection', MAX_POLICIES).map((item): PolicySummary => {
    if (!isObject(item)) throw new Error('Invalid policy.');
    return {
      id: safeString(item.id, 'policy ID', 128),
      name: safeString(item.name, 'policy name', 128),
      protocol: safeString(item.protocol, 'policy protocol', 128),
      sources: references(stringArray(item.sources, 'policy sources'), addressNames),
      sourcePorts: stringArray(item.source_ports, 'policy source ports'),
      destinations: references(stringArray(item.destinations, 'policy destinations'), addressNames),
      destinationPorts: stringArray(item.destination_ports, 'policy destination ports'),
      features: stringArray(item.features, 'policy features'),
      action: safeString(item.action, 'policy action', 32),
      nat: optionalString(item.nat, 'policy NAT'),
      routing: optionalString(item.routing, 'policy routing'),
      tlsProfile: optionalString(item.tls_profile, 'policy TLS profile'),
      sshProfile: optionalString(item.ssh_profile, 'policy SSH profile'),
      detectionProfile: optionalString(item.detection_profile, 'policy detection profile'),
      contentProfile: optionalString(item.content_profile, 'policy content profile'),
      authProfile: optionalString(item.auth_profile, 'policy authentication profile'),
      dnsProfile: optionalString(item.dns_profile, 'policy DNS profile'),
      scriptProfile: optionalString(item.script_profile, 'policy script profile'),
      enabled: safeBoolean(item.enabled, 'policy enabled state'),
    };
  });

  const policyIds = new Set<string>();
  for (const policy of policies) {
    if (policyIds.has(policy.id)) throw new Error('Duplicate policy ID.');
    policyIds.add(policy.id);
    for (const reference of [...policy.sources, ...policy.destinations]) {
      if (reference.id === null) continue;
      const address = addressesById.get(reference.id);
      if (address && !address.usedBy.some(item => item.id === policy.id)) {
        address.usedBy.push({id: policy.id, kind: 'policy', name: policy.name});
      }
    }
  }

  const ports = boundedArray(value.ports, 'port collection', MAX_OBJECTS).map((item): MutablePort => {
    if (!isObject(item)) throw new Error('Invalid port object.');
    const start = safeInteger(item.start, 'port start', 65535);
    const end = safeInteger(item.end, 'port end', 65535);
    if (start > end) throw new Error('Invalid port range.');
    return {
      id: safeString(item.id, 'port ID', 128),
      name: safeString(item.name, 'port name', 128),
      start,
      end,
      usedBy: [],
    };
  });
  const protocols = boundedArray(value.protocols, 'protocol collection', MAX_OBJECTS).map((item): MutableProtocol => {
    if (!isObject(item)) throw new Error('Invalid protocol object.');
    return {
      id: safeString(item.id, 'protocol ID', 128),
      name: safeString(item.name, 'protocol name', 128),
      number: safeInteger(item.number, 'protocol number', 255),
      usedBy: [],
    };
  });
  const profiles = boundedArray(value.profiles, 'profile collection', MAX_OBJECTS).map((item): MutableProfile => {
    if (!isObject(item)) throw new Error('Invalid profile.');
    const type = safeString(item.type, 'profile type', 32);
    let routing: ProfileObject['routing'] = null;
    let tls: ProfileObject['tls'] = null;
    let detection: ProfileObject['detection'] = null;
    let content: ProfileObject['content'] = null;
    let ssh: ProfileObject['ssh'] = null;
    let dns: ProfileObject['dns'] = null;
    let script: ProfileObject['script'] = null;
    let authentication: ProfileObject['authentication'] = null;
    if (type === 'routing') {
      if (!isObject(item.routing)) throw new Error('Invalid routing profile.');
      const loadBalancingMethod = safeString(item.routing.load_balancing_method, 'routing load-balancing method', 32);
      if (!['round-robin', 'sticky-l3', 'sticky-l4'].includes(loadBalancingMethod)) {
        throw new Error('Invalid routing load-balancing method.');
      }
      const rewriteSni = optionalString(item.routing.rewrite_sni, 'routing source SNI', 1024);
      const rewriteSniTo = optionalString(item.routing.rewrite_sni_to, 'routing destination SNI', 1024);
      if ((rewriteSni.length === 0) !== (rewriteSniTo.length === 0)) throw new Error('Invalid routing SNI rewrite.');
      routing = {
        destinationAddresses: stringArray(item.routing.destination_addresses, 'routing destination addresses'),
        destinationPorts: stringArray(item.routing.destination_ports, 'routing destination ports'),
        loadBalancingMethod: loadBalancingMethod as 'round-robin' | 'sticky-l3' | 'sticky-l4',
        rewriteSni,
        rewriteSniTo,
      };
    } else if (item.routing !== null) {
      throw new Error('Invalid non-routing profile details.');
    }
    if (type === 'tls') {
      if (!isObject(item.tls)) throw new Error('Invalid TLS profile.');
      const alerts = safeString(item.tls.alerts, 'TLS alert mode', 16);
      if (!['all', 'unusual', 'mute'].includes(alerts)) throw new Error('Invalid TLS alert mode.');
      const clientCertificateAction = safeString(
        item.tls.client_certificate_action, 'TLS client certificate action', 32,
      );
      if (!['block_or_replacement', 'empty_client_cert', 'tls_bypass', 'use_configured'].includes(clientCertificateAction)) {
        throw new Error('Invalid TLS client certificate action.');
      }
      tls = {
        inspect: safeBoolean(item.tls.inspect, 'TLS inspection state'),
        allowUntrustedIssuers: safeBoolean(item.tls.allow_untrusted_issuers, 'TLS untrusted issuer state'),
        allowInvalidCertificates: safeBoolean(item.tls.allow_invalid_certificates, 'TLS invalid certificate state'),
        allowSelfSigned: safeBoolean(item.tls.allow_self_signed, 'TLS self-signed state'),
        certificateTransparency: safeBoolean(item.tls.certificate_transparency, 'TLS transparency state'),
        ocspStapling: safeBoolean(item.tls.ocsp_stapling, 'TLS OCSP stapling state'),
        blockAlpn: safeBoolean(item.tls.block_alpn, 'TLS ALPN state'),
        onlyCustomCertificates: safeBoolean(item.tls.only_custom_certificates, 'TLS custom certificate state'),
        noFallbackBypass: safeBoolean(item.tls.no_fallback_bypass, 'TLS fallback state'),
        sslKeyLog: safeBoolean(item.tls.ssl_key_log, 'TLS key log state'),
        clientHelloTimeoutMs: safeInteger(item.tls.client_hello_timeout_ms, 'TLS client hello timeout', 3600000),
        handshakeTimeoutMs: safeInteger(item.tls.handshake_timeout_ms, 'TLS handshake timeout', 3600000),
        sniBypassEntries: safeInteger(item.tls.sni_bypass_entries, 'TLS SNI bypass count', MAX_REFERENCES),
        clientCertificateAction,
        alerts: alerts as 'all' | 'unusual' | 'mute',
      };
      if (tls.clientHelloTimeoutMs === 0 || tls.handshakeTimeoutMs === 0) throw new Error('Invalid TLS timeout.');
    } else if (item.tls !== null) {
      throw new Error('Invalid non-TLS profile details.');
    }
    if (type === 'detection') {
      if (!isObject(item.detection)) throw new Error('Invalid detection profile.');
      const mode = safeInteger(item.detection.mode, 'detection mode', 2) as 0 | 1 | 2;
      detection = {
        mode,
        enginesEnabled: safeBoolean(item.detection.engines_enabled, 'detection engine state'),
        knowledgeBaseEnabled: safeBoolean(
          item.detection.knowledge_base_enabled, 'detection knowledge-base state',
        ),
      };
    } else if (item.detection !== null) {
      throw new Error('Invalid non-detection profile details.');
    }
    if (type === 'content') {
      if (!isObject(item.content)) throw new Error('Invalid content profile.');
      const writeFormat = safeString(item.content.write_format, 'content capture format', 16);
      if (!['smcap', 'pcap', 'pcap_single'].includes(writeFormat)) throw new Error('Invalid content capture format.');
      content = {
        writePayload: safeBoolean(item.content.write_payload, 'content payload state'),
        writeFormat: writeFormat as 'smcap' | 'pcap' | 'pcap_single',
        webhookEnabled: safeBoolean(item.content.webhook_enabled, 'content webhook state'),
        webhookLocksTraffic: safeBoolean(item.content.webhook_locks_traffic, 'content webhook lock state'),
        ja4TlsClientHello: safeBoolean(item.content.ja4_tls_client_hello, 'content JA4 client state'),
        ja4TlsClientHelloIgnoresSni: safeBoolean(
          item.content.ja4_tls_client_hello_ignores_sni, 'content JA4 SNI state',
        ),
        ja4TlsServerHello: safeBoolean(item.content.ja4_tls_server_hello, 'content JA4 server state'),
        ja4Http: safeBoolean(item.content.ja4_http, 'content JA4 HTTP state'),
        sessionFilterConfigured: safeBoolean(
          item.content.session_filter_configured, 'content session-filter state',
        ),
        ruleCount: safeInteger(item.content.rule_count, 'content rule count', MAX_REFERENCES),
      };
    } else if (item.content !== null) {
      throw new Error('Invalid non-content profile details.');
    }
    if (type === 'ssh') {
      if (!isObject(item.ssh)) throw new Error('Invalid SSH profile.');
      const hostKeyPolicy = safeString(item.ssh.host_key_policy, 'SSH host-key policy', 16);
      if (!['insecure', 'accept-new', 'strict'].includes(hostKeyPolicy)) throw new Error('Invalid SSH host-key policy.');
      ssh = {
        hostKeyConfigured: safeBoolean(item.ssh.host_key_configured, 'SSH host-key state'),
        hostKeyPolicy: hostKeyPolicy as 'insecure' | 'accept-new' | 'strict',
        shell: safeBoolean(item.ssh.shell, 'SSH shell action'),
        exec: safeBoolean(item.ssh.exec, 'SSH exec action'),
        subsystem: safeBoolean(item.ssh.subsystem, 'SSH subsystem action'),
        pty: safeBoolean(item.ssh.pty, 'SSH PTY action'),
        environment: safeBoolean(item.ssh.environment, 'SSH environment action'),
        localForward: safeBoolean(item.ssh.local_forward, 'SSH local-forward action'),
        remoteForward: safeBoolean(item.ssh.remote_forward, 'SSH remote-forward action'),
        x11: safeBoolean(item.ssh.x11, 'SSH X11 action'),
        agent: safeBoolean(item.ssh.agent, 'SSH agent action'),
      };
    } else if (item.ssh !== null) {
      throw new Error('Invalid non-SSH profile details.');
    }
    if (type === 'dns') {
      if (!isObject(item.dns)) throw new Error('Invalid DNS ALG profile.');
      dns = {
        matchRequestId: safeBoolean(item.dns.match_request_id, 'DNS request-ID matching state'),
        randomizeId: safeBoolean(item.dns.randomize_id, 'DNS randomization state'),
        cachedResponses: safeBoolean(item.dns.cached_responses, 'DNS cache response state'),
      };
    } else if (item.dns !== null) {
      throw new Error('Invalid non-DNS profile details.');
    }
    if (type === 'script') {
      if (!isObject(item.script)) throw new Error('Invalid script profile.');
      const runtime = safeString(item.script.runtime, 'script runtime', 16);
      if (!['python', 'go', 'unknown'].includes(runtime)) throw new Error('Invalid script runtime.');
      script = {
        runtime: runtime as 'python' | 'go' | 'unknown',
        modulePathConfigured: safeBoolean(item.script.module_path_configured, 'script module-path state'),
      };
    } else if (item.script !== null) {
      throw new Error('Invalid non-script profile details.');
    }
    if (type === 'authentication') {
      if (!isObject(item.authentication) || item.authentication.deprecated !== true) {
        throw new Error('Invalid authentication profile.');
      }
      authentication = {
        authenticate: safeBoolean(item.authentication.authenticate, 'authentication state'),
        resolve: safeBoolean(item.authentication.resolve, 'authentication resolution state'),
        identityCount: safeInteger(item.authentication.identity_count, 'authentication identity count', MAX_REFERENCES),
        deprecated: true,
      };
    } else if (item.authentication !== null) {
      throw new Error('Invalid non-authentication profile details.');
    }
    return {
      id: safeString(item.id, 'profile ID', 128),
      name: safeString(item.name, 'profile name', 128),
      type,
      routing,
      tls,
      detection,
      content,
      ssh,
      dns,
      script,
      authentication,
      usedBy: [],
    };
  });
  for (const collection of [ports, protocols, profiles]) {
    const ids = new Set<string>();
    const names = new Set<string>();
    for (const item of collection) {
      if (ids.has(item.id) || names.has(item.name)) throw new Error('Duplicate configuration object.');
      ids.add(item.id);
      names.add(item.name);
    }
  }
  const portsByName = new Map(ports.map(item => [item.name, item]));
  const protocolsByName = new Map(protocols.map(item => [item.name, item]));
  const profilesByIdentity = new Map(profiles.map(item => [`${item.type}:${item.name}`, item]));
  for (const policy of policies) {
    const usage: Usage = {id: policy.id, kind: 'policy', name: policy.name};
    protocolsByName.get(policy.protocol)?.usedBy.push(usage);
    profilesByIdentity.get(`tls:${policy.tlsProfile}`)?.usedBy.push(usage);
    profilesByIdentity.get(`routing:${policy.routing}`)?.usedBy.push(usage);
    profilesByIdentity.get(`ssh:${policy.sshProfile}`)?.usedBy.push(usage);
    profilesByIdentity.get(`detection:${policy.detectionProfile}`)?.usedBy.push(usage);
    profilesByIdentity.get(`content:${policy.contentProfile}`)?.usedBy.push(usage);
    profilesByIdentity.get(`authentication:${policy.authProfile}`)?.usedBy.push(usage);
    profilesByIdentity.get(`dns:${policy.dnsProfile}`)?.usedBy.push(usage);
    profilesByIdentity.get(`script:${policy.scriptProfile}`)?.usedBy.push(usage);
    for (const name of new Set([...policy.sourcePorts, ...policy.destinationPorts])) {
      portsByName.get(name)?.usedBy.push(usage);
    }
  }
  for (const profile of profiles) {
    if (!profile.routing) continue;
    const usage: Usage = {id: profile.id, kind: 'routing-profile', name: profile.name};
    for (const name of new Set(profile.routing.destinationAddresses)) {
      const address = addressNames.get(name);
      if (address && !address.usedBy.some(item => item.id === profile.id)) address.usedBy.push(usage);
    }
    for (const name of new Set(profile.routing.destinationPorts)) {
      const port = portsByName.get(name);
      if (port && !port.usedBy.some(item => item.id === profile.id)) port.usedBy.push(usage);
    }
  }

  let settings: SystemSettings | null = null;
  if (value.settings !== null) {
    if (!isObject(value.settings) || !isObject(value.settings.workers) ||
        !isObject(value.settings.http_api) || !isObject(value.settings.webhook)) {
      throw new Error('Invalid system settings.');
    }
    settings = {
      acceptTproxy: safeBoolean(value.settings.accept_tproxy, 'TPROXY listener state'),
      acceptRedirect: safeBoolean(value.settings.accept_redirect, 'REDIRECT listener state'),
      acceptSocks: safeBoolean(value.settings.accept_socks, 'SOCKS listener state'),
      acceptHttpConnect: safeBoolean(value.settings.accept_http_connect, 'HTTP CONNECT listener state'),
      acceptApi: safeBoolean(value.settings.accept_api, 'Smithproxy API listener state'),
      policyFailOpen: safeBoolean(value.settings.policy_fail_open, 'policy fail-open state'),
      accessRequestFailOpen: safeBoolean(
        value.settings.access_request_fail_open, 'access-request fail-open state',
      ),
      workers: {
        plaintext: safeInteger(value.settings.workers.plaintext, 'plaintext workers', 4096),
        tls: safeInteger(value.settings.workers.tls, 'TLS workers', 4096),
        udp: safeInteger(value.settings.workers.udp, 'UDP workers', 4096),
        dtls: safeInteger(value.settings.workers.dtls, 'DTLS workers', 4096),
        quic: safeInteger(value.settings.workers.quic, 'QUIC workers', 4096),
        socks: safeInteger(value.settings.workers.socks, 'SOCKS workers', 4096),
        httpConnect: safeInteger(value.settings.workers.http_connect, 'HTTP CONNECT workers', 4096),
      },
      tlsAutodetect: safeBoolean(value.settings.tls_autodetect, 'TLS autodetection state'),
      tlsAutodetectHarder: safeBoolean(value.settings.tls_autodetect_harder, 'hard TLS autodetection state'),
      kernelTls: safeBoolean(value.settings.kernel_tls, 'kernel TLS state'),
      nameserverCount: safeInteger(value.settings.nameserver_count, 'nameserver count', MAX_REFERENCES),
      httpApi: {
        keyCount: safeInteger(value.settings.http_api.key_count, 'API key count', MAX_REFERENCES),
        allowedIpCount: safeInteger(value.settings.http_api.allowed_ip_count, 'API allowed-IP count', MAX_REFERENCES),
        loopbackOnly: safeBoolean(value.settings.http_api.loopback_only, 'API loopback state'),
        pamLogin: safeBoolean(value.settings.http_api.pam_login, 'API PAM state'),
        allowApiHeader: safeBoolean(value.settings.http_api.allow_api_header, 'API header state'),
      },
      webhook: {
        enabled: safeBoolean(value.settings.webhook.enabled, 'webhook state'),
        tlsVerify: safeBoolean(value.settings.webhook.tls_verify, 'webhook TLS verification state'),
        urlConfigured: safeBoolean(value.settings.webhook.url_configured, 'webhook URL state'),
        siftEnabled: safeBoolean(value.settings.webhook.sift_enabled, 'Sift state'),
        apiOverride: safeBoolean(value.settings.webhook.api_override, 'webhook API override state'),
      },
    };
  }
  let captures: CaptureSettings | null = null;
  let debug: DebugSettings | null = null;
  if (value.debug !== null) {
    if (!isObject(value.debug)) throw new Error('Invalid debug settings.');
    debug = {
      logDataCrc: safeBoolean(value.debug.log_data_crc, 'payload CRC logging state'),
      logSockets: safeBoolean(value.debug.log_sockets, 'socket logging state'),
      logOnlineConnectionName: safeBoolean(
        value.debug.log_online_cx_name, 'online connection-name logging state',
      ),
      logSourceLines: safeBoolean(value.debug.log_srclines, 'source-line logging state'),
      logSourceLinesAlways: safeBoolean(
        value.debug.log_srclines_always, 'unconditional source-line logging state',
      ),
      moduleOverrideCount: safeInteger(
        value.debug.module_override_count, 'debug module override count', MAX_OBJECTS,
      ),
    };
  }
  if (value.captures !== null) {
    if (!isObject(value.captures) || !isObject(value.captures.local) || !isObject(value.captures.remote)) {
      throw new Error('Invalid capture settings.');
    }
    const localFormat = safeString(value.captures.local.format, 'local capture format', 16);
    const tunnelType = safeString(value.captures.remote.tunnel_type, 'remote capture tunnel', 16);
    const greFormat = safeString(value.captures.remote.gre_format, 'remote capture format', 16);
    if (!['pcap_single', 'pcap', 'smcap'].includes(localFormat) || tunnelType !== 'gre' ||
        !['traffic', 'pcapng'].includes(greFormat)) {
      throw new Error('Invalid capture format.');
    }
    captures = {
      local: {
        enabled: safeBoolean(value.captures.local.enabled, 'local capture state'),
        directoryConfigured: safeBoolean(
          value.captures.local.directory_configured, 'local capture directory state',
        ),
        format: localFormat as 'pcap_single' | 'pcap' | 'smcap',
        quotaMiB: safeInteger(value.captures.local.quota_mib, 'local capture quota', 1024 * 1024),
      },
      remote: {
        enabled: safeBoolean(value.captures.remote.enabled, 'remote capture state'),
        tunnelType: 'gre',
        greFormat: greFormat as 'traffic' | 'pcapng',
        destinationConfigured: safeBoolean(
          value.captures.remote.destination_configured, 'remote capture destination state',
        ),
        ttl: safeInteger(value.captures.remote.ttl, 'remote capture TTL', 255),
        bindInterfaceConfigured: safeBoolean(
          value.captures.remote.bind_interface_configured, 'remote capture interface state',
        ),
      },
      calculateChecksums: safeBoolean(value.captures.calculate_checksums, 'capture checksum state'),
    };
  }
  let securityAssets: SecurityAssets | null = null;
  if (value.security_assets !== null) {
    if (!isObject(value.security_assets)) throw new Error('Invalid security asset posture.');
    securityAssets = {
      certificateAuthorityCount: safeInteger(
        value.security_assets.certificate_authority_count, 'certificate authority count', MAX_OBJECTS,
      ),
      certificateAuthorityPathCount: safeInteger(
        value.security_assets.certificate_authority_path_count, 'certificate authority path count', MAX_OBJECTS,
      ),
      starttlsSignatureCount: safeInteger(
        value.security_assets.starttls_signature_count, 'STARTTLS signature count', MAX_OBJECTS,
      ),
      starttlsFlowStepCount: safeInteger(
        value.security_assets.starttls_flow_step_count, 'STARTTLS flow-step count', MAX_OBJECTS * MAX_REFERENCES,
      ),
      detectionSignatureCount: safeInteger(
        value.security_assets.detection_signature_count, 'detection signature count', MAX_OBJECTS,
      ),
      detectionFlowStepCount: safeInteger(
        value.security_assets.detection_flow_step_count, 'detection flow-step count', MAX_OBJECTS * MAX_REFERENCES,
      ),
    };
    if (securityAssets.certificateAuthorityPathCount > securityAssets.certificateAuthorityCount) {
      throw new Error('Invalid certificate authority posture.');
    }
  }
  if (typeof value.augment_support !== 'boolean' || !Array.isArray(value.value_origins) ||
      value.value_origins.length > MAX_OBJECTS * 16) {
    throw new Error('Invalid augment provenance envelope.');
  }
  const originPaths = new Set<string>();
  const valueOrigins = value.value_origins.map((item): ValueOrigin => {
    if (!isObject(item) || typeof item.path !== 'string' || item.path.length === 0 ||
        item.path.length > 512 || originPaths.has(item.path) ||
        !/^[A-Za-z0-9_.\[\]-]+$/u.test(item.path) || typeof item.editable !== 'boolean' ||
        !Array.isArray(item.layers) || item.layers.length === 0 || item.layers.length > 64) {
      throw new Error('Invalid value provenance entry.');
    }
    originPaths.add(item.path);
    const layerIds = new Set<string>();
    const layers = item.layers.map(layer => {
      if (!isObject(layer) || typeof layer.id !== 'string' || layer.id.length === 0 ||
          layer.id.length > 128 || layerIds.has(layer.id) ||
          !(layer.priority === null || (typeof layer.priority === 'number' &&
            Number.isSafeInteger(layer.priority) && layer.priority >= 0))) {
        throw new Error('Invalid augment layer.');
      }
      layerIds.add(layer.id);
      return {id: layer.id, priority: layer.priority};
    });
    const persistentValue = configScalar(item.persistent_value, 'persistent value');
    const effectiveValue = configScalar(item.effective_value, 'effective value');
    if (typeof persistentValue !== typeof effectiveValue) throw new Error('Inconsistent value provenance types.');
    return {path: item.path, persistentValue, effectiveValue, layers, editable: item.editable};
  });
  if (!value.augment_support && valueOrigins.length !== 0) {
    throw new Error('Unexpected provenance without augment support.');
  }

  return {
    source: 'live',
    state: value.state as ConfigSnapshot['state'],
    detail: value.detail,
    checkedAtUnixMs: nullableInteger(value.checked_at_unix_ms, 'configuration check time'),
    lastSuccessAtUnixMs: nullableInteger(value.last_success_at_unix_ms, 'configuration success time'),
    revision: value.revision as string | null,
    policies,
    addresses,
    ports,
    protocols,
    profiles,
    settings,
    debug,
    captures,
    securityAssets,
    augmentSupport: value.augment_support,
    valueOrigins,
  };
}

export class ApiConfigClient implements ConfigClient {
  readonly #endpoint: string;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;

  constructor(apiBase: string, fetchImplementation: typeof fetch = (input, init) => fetch(input, init), timeoutMs = 5000) {
    const base = normalizedPath(apiBase);
    this.#endpoint = base === '/' ? '/config/snapshot' : `${base}/config/snapshot`;
    this.#fetch = fetchImplementation;
    this.#timeoutMs = timeoutMs;
  }

  async loadSnapshot(): Promise<ConfigSnapshot> {
    const controller = new AbortController();
    const timeout = globalThis.setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const response = await this.#fetch(this.#endpoint, {
        cache: 'no-store',
        credentials: 'same-origin',
        headers: {Accept: 'application/json'},
        redirect: 'error',
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`Configuration API returned HTTP ${response.status}.`);
      return parseConfigSnapshot(await boundedJson(response));
    } finally {
      globalThis.clearTimeout(timeout);
    }
  }
}
