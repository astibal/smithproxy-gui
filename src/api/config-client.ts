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
import {httpStatusError} from './http-error';
import {isCanonicalRevisionOrNull} from './revision';
import {boundedJson} from './bounded-json';

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

function rangedInteger(value: unknown, label: string, minimum: number, maximum: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`Invalid ${label}.`);
  }
  return value;
}

function allowedInteger(value: unknown, label: string, allowed: ReadonlyArray<number>): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || !allowed.includes(value)) {
    throw new Error(`Invalid ${label}.`);
  }
  return value;
}

function allowedString(value: unknown, label: string, allowed: ReadonlyArray<string>): string {
  const result = safeString(value, label, 128);
  if (!allowed.includes(result)) throw new Error(`Invalid ${label}.`);
  return result;
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
      !isCanonicalRevisionOrNull(value.revision)) {
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
  const contentRuleIds = new Set<string>();
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
      const redirectWarningPorts = boundedArray(
        item.tls.redirect_warning_ports, 'TLS redirect warning ports', MAX_REFERENCES,
      ).map(port => safeInteger(port, 'TLS redirect warning port', 65535));
      if (new Set(redirectWarningPorts).size !== redirectWarningPorts.length) {
        throw new Error('Duplicate TLS redirect warning port.');
      }
      tls = {
        inspect: safeBoolean(item.tls.inspect, 'TLS inspection state'),
        usePfs: safeBoolean(item.tls.use_pfs, 'TLS PFS state'),
        leftUsePfs: safeBoolean(item.tls.left_use_pfs, 'TLS downstream PFS state'),
        rightUsePfs: safeBoolean(item.tls.right_use_pfs, 'TLS upstream PFS state'),
        leftDisableReuse: safeBoolean(item.tls.left_disable_reuse, 'TLS downstream reuse state'),
        rightDisableReuse: safeBoolean(item.tls.right_disable_reuse, 'TLS upstream reuse state'),
        allowUntrustedIssuers: safeBoolean(item.tls.allow_untrusted_issuers, 'TLS untrusted issuer state'),
        allowInvalidCertificates: safeBoolean(item.tls.allow_invalid_certificates, 'TLS invalid certificate state'),
        allowSelfSigned: safeBoolean(item.tls.allow_self_signed, 'TLS self-signed state'),
        certificateTransparency: safeBoolean(item.tls.certificate_transparency, 'TLS transparency state'),
        ocspMode: safeInteger(item.tls.ocsp_mode, 'TLS OCSP mode', 2) as 0 | 1 | 2,
        ocspStapling: safeBoolean(item.tls.ocsp_stapling, 'TLS OCSP stapling state'),
        ocspStaplingMode: safeInteger(item.tls.ocsp_stapling_mode, 'TLS OCSP stapling mode', 2) as 0 | 1 | 2,
        blockAlpn: safeBoolean(item.tls.block_alpn, 'TLS ALPN state'),
        sniBasedCertificates: safeBoolean(item.tls.sni_based_certificates, 'TLS SNI certificate state'),
        ipBasedCertificates: safeBoolean(item.tls.ip_based_certificates, 'TLS IP certificate state'),
        onlyCustomCertificates: safeBoolean(item.tls.only_custom_certificates, 'TLS custom certificate state'),
        noFallbackBypass: safeBoolean(item.tls.no_fallback_bypass, 'TLS fallback state'),
        sniFilterUsesDnsCache: safeBoolean(item.tls.sni_filter_uses_dns_cache, 'TLS SNI DNS-cache state'),
        sniFilterUsesDnsDomainTree: safeBoolean(
          item.tls.sni_filter_uses_dns_domain_tree, 'TLS SNI DNS-tree state',
        ),
        redirectWarningPorts,
        failedCertificateReplacement: safeBoolean(
          item.tls.failed_certificate_replacement, 'TLS failed-certificate replacement state',
        ),
        failedCertificateOverride: safeBoolean(
          item.tls.failed_certificate_override, 'TLS failed-certificate override state',
        ),
        failedCertificateOverrideTimeout: safeInteger(
          item.tls.failed_certificate_override_timeout, 'TLS failed-certificate override timeout', 2147483647,
        ),
        failedCertificateOverrideTimeoutType: safeInteger(
          item.tls.failed_certificate_override_timeout_type, 'TLS failed-certificate timeout type', 1,
        ) as 0 | 1,
        sslKeyLog: safeBoolean(item.tls.ssl_key_log, 'TLS key log state'),
        clientHelloTimeoutMs: safeInteger(item.tls.client_hello_timeout_ms, 'TLS client hello timeout', 2147483647),
        handshakeTimeoutMs: safeInteger(item.tls.handshake_timeout_ms, 'TLS handshake timeout', 2147483647),
        sniBypassEntries: safeInteger(item.tls.sni_bypass_entries, 'TLS SNI bypass count', MAX_REFERENCES),
        clientCertificateAction,
        alerts: alerts as 'all' | 'unusual' | 'mute',
      };
      if (tls.clientHelloTimeoutMs === 0 || tls.handshakeTimeoutMs === 0 ||
          tls.failedCertificateOverrideTimeout === 0) throw new Error('Invalid TLS timeout.');
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
      const rules = boundedArray(item.content.rules, 'content rules', MAX_REFERENCES).map(rule => {
        if (!isObject(rule)) throw new Error('Invalid content rule.');
        const id = safeString(rule.id, 'content rule ID', 128);
        const matchConfigured = safeBoolean(rule.match_configured, 'content rule match state');
        const replacementConfigured = safeBoolean(
          rule.replacement_configured, 'content rule replacement state',
        );
        const replacementHasValue = safeBoolean(
          rule.replacement_has_value, 'content rule replacement value state',
        );
        const fillLength = safeBoolean(rule.fill_length, 'content rule fill-length state');
        const replaceEachNth = rangedInteger(
          rule.replace_each_nth, 'content rule replacement interval', -2147483648, 2147483647,
        );
        if (contentRuleIds.has(id) || !matchConfigured || (replacementHasValue && !replacementConfigured)) {
          throw new Error('Invalid content rule posture.');
        }
        contentRuleIds.add(id);
        return {
          id, matchConfigured: true as const, replacementConfigured, replacementHasValue,
          fillLength, replaceEachNth,
        };
      });
      const ruleCount = safeInteger(item.content.rule_count, 'content rule count', MAX_REFERENCES);
      if (ruleCount !== rules.length) throw new Error('Invalid content rule count.');
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
        ruleCount,
        rules,
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
    if (!isObject(value.settings) || !isObject(value.settings.workers) || !isObject(value.settings.ports) ||
        !isObject(value.settings.logging) || !isObject(value.settings.auxiliary) ||
        !isObject(value.settings.auxiliary.tuning) ||
        !isObject(value.settings.http_api) ||
        !isObject(value.settings.webhook)) {
      throw new Error('Invalid system settings.');
    }
    const nameservers = stringArray(value.settings.nameservers, 'nameserver');
    const udpQuickPorts = stringArray(value.settings.auxiliary.udp_quick_ports, 'UDP quick port');
    const allowedIps = stringArray(value.settings.http_api.allowed_ips, 'API allowed IP');
    if (udpQuickPorts.some(port => !/^\d{1,5}$/u.test(port) || Number(port) > 65535) ||
        value.settings.nameserver_count !== nameservers.length ||
        value.settings.auxiliary.udp_quick_port_count !== udpQuickPorts.length ||
        value.settings.http_api.allowed_ip_count !== allowedIps.length) {
      throw new Error('Invalid system address or quick-port collection.');
    }
    settings = {
      acceptTproxy: safeBoolean(value.settings.accept_tproxy, 'TPROXY listener state'),
      acceptRedirect: safeBoolean(value.settings.accept_redirect, 'REDIRECT listener state'),
      acceptSocks: safeBoolean(value.settings.accept_socks, 'SOCKS listener state'),
      acceptHttpConnect: safeBoolean(value.settings.accept_http_connect, 'HTTP CONNECT listener state'),
      acceptApi: safeBoolean(value.settings.accept_api, 'Smithproxy API listener state'),
      extendedLocalDestinationProtection: safeBoolean(
        value.settings.extended_local_destination_protection, 'local destination protection state',
      ),
      policyFailOpen: safeBoolean(value.settings.policy_fail_open, 'policy fail-open state'),
      accessRequestFailOpen: safeBoolean(
        value.settings.access_request_fail_open, 'access-request fail-open state',
      ),
      workers: {
        plaintext: rangedInteger(value.settings.workers.plaintext, 'plaintext workers', -1, 4096),
        tls: rangedInteger(value.settings.workers.tls, 'TLS workers', -1, 4096),
        udp: rangedInteger(value.settings.workers.udp, 'UDP workers', -1, 4096),
        dtls: rangedInteger(value.settings.workers.dtls, 'DTLS workers', -1, 4096),
        quic: rangedInteger(value.settings.workers.quic, 'QUIC workers', -1, 4096),
        socks: rangedInteger(value.settings.workers.socks, 'SOCKS workers', -1, 4096),
        httpConnect: rangedInteger(value.settings.workers.http_connect, 'HTTP CONNECT workers', -1, 4096),
      },
      ports: {
        plaintext: safeInteger(value.settings.ports.plaintext, 'plaintext port', 65535),
        tls: safeInteger(value.settings.ports.tls, 'TLS port', 65535),
        udp: safeInteger(value.settings.ports.udp, 'UDP port', 65535),
        dtls: safeInteger(value.settings.ports.dtls, 'DTLS port', 65535),
        quic: safeInteger(value.settings.ports.quic, 'QUIC port', 65535),
        socks: safeInteger(value.settings.ports.socks, 'SOCKS port', 65535),
        httpConnect: safeInteger(value.settings.ports.http_connect, 'HTTP CONNECT port', 65535),
      },
      ocspStatusTtl: safeInteger(value.settings.ocsp_status_ttl, 'OCSP status TTL', 31536000),
      crlStatusTtl: safeInteger(value.settings.crl_status_ttl, 'CRL status TTL', 31536000),
      logging: {
        defaultWritePayload: safeBoolean(
          value.settings.logging.default_write_payload, 'default payload capture state',
        ),
        payloadDirectoryConfigured: safeBoolean(
          value.settings.logging.payload_directory_configured, 'payload directory state',
        ),
        pcapSingleQuota: safeInteger(
          value.settings.logging.pcap_single_quota, 'single PCAP quota', 1024 * 1024,
        ),
        level: safeInteger(value.settings.logging.level, 'log level', 10),
        fileConfigured: safeBoolean(value.settings.logging.file_configured, 'log file state'),
        console: safeBoolean(value.settings.logging.console, 'console logging state'),
        sslKeyFileConfigured: safeBoolean(
          value.settings.logging.ssl_key_file_configured, 'TLS key log file state',
        ),
        syslogServerConfigured: safeBoolean(
          value.settings.logging.syslog_server_configured, 'syslog server state',
        ),
        syslogPort: safeInteger(value.settings.logging.syslog_port, 'syslog port', 65535),
        syslogFacility: safeInteger(value.settings.logging.syslog_facility, 'syslog facility', 23),
        syslogLevel: safeInteger(value.settings.logging.syslog_level, 'syslog level', 10),
        syslogFamily: allowedInteger(value.settings.logging.syslog_family, 'syslog family', [4, 6]) as 4 | 6,
      },
      auxiliary: {
        udpQuickPortCount: safeInteger(
          value.settings.auxiliary.udp_quick_port_count, 'UDP quick-port count', MAX_REFERENCES,
        ),
        udpQuickPorts,
        certificatesPathConfigured: safeBoolean(
          value.settings.auxiliary.certificates_path_configured, 'certificate path state',
        ),
        certificatePasswordConfigured: safeBoolean(
          value.settings.auxiliary.certificate_password_configured, 'certificate password state',
        ),
        certificateTransparencyLogConfigured: safeBoolean(
          value.settings.auxiliary.certificate_transparency_log_configured,
          'certificate transparency log state',
        ),
        caBundlePathConfigured: safeBoolean(
          value.settings.auxiliary.ca_bundle_path_configured, 'CA bundle path state',
        ),
        caBundleFileConfigured: safeBoolean(
          value.settings.auxiliary.ca_bundle_file_configured, 'CA bundle file state',
        ),
        messagesDirectoryConfigured: safeBoolean(
          value.settings.auxiliary.messages_directory_configured, 'message directory state',
        ),
        payloadFilePrefixConfigured: safeBoolean(
          value.settings.auxiliary.payload_file_prefix_configured, 'payload prefix state',
        ),
        payloadFileSuffixConfigured: safeBoolean(
          value.settings.auxiliary.payload_file_suffix_configured, 'payload suffix state',
        ),
        cliPort: safeInteger(value.settings.auxiliary.cli_port, 'CLI port', 65535),
        cliPasswordConfigured: safeBoolean(
          value.settings.auxiliary.cli_password_configured, 'CLI password state',
        ),
        webRatingKeyConfigured: safeBoolean(
          value.settings.auxiliary.web_rating_key_configured, 'web-rating key state',
        ),
        adminGroupConfigured: safeBoolean(
          value.settings.auxiliary.admin_group_configured, 'administration group state',
        ),
        tuning: {
          hostBufferMin: rangedInteger(
            value.settings.auxiliary.tuning.host_buffer_min, 'host buffer minimum', 1500, 10000000,
          ),
          hostBufferMaxMultiplier: rangedInteger(
            value.settings.auxiliary.tuning.host_buffer_max_multiplier,
            'host buffer maximum multiplier', 1, 1024000000,
          ),
          hostWriteFull: rangedInteger(
            value.settings.auxiliary.tuning.host_write_full, 'host write threshold', 1024, 1024000000,
          ),
          hostIoBatch: rangedInteger(
            value.settings.auxiliary.tuning.host_io_batch, 'host I/O batch', 16384, 16777216,
          ),
          tlsWriteChunk: rangedInteger(
            value.settings.auxiliary.tuning.tls_write_chunk, 'TLS write chunk', 1024, 1048576,
          ),
          hostOpenTimeout: safeInteger(
            value.settings.auxiliary.tuning.host_open_timeout, 'host open timeout', 65535,
          ),
          hostIdleTimeout: safeInteger(
            value.settings.auxiliary.tuning.host_idle_timeout, 'host idle timeout', 65535,
          ),
          neighborCacheSize: rangedInteger(
            value.settings.auxiliary.tuning.neighbor_cache_size,
            'neighbor cache size', 1, 2147483647,
          ),
        },
        threadPoolLogging: safeBoolean(
          value.settings.auxiliary.thread_pool_logging, 'thread-pool logging state',
        ),
        socksAsyncDns: safeBoolean(value.settings.auxiliary.socks_async_dns, 'SOCKS async DNS state'),
        socksIpVersionMixing: safeBoolean(
          value.settings.auxiliary.socks_ip_version_mixing, 'SOCKS IP-version mixing state',
        ),
        socksPreferIpv6: safeBoolean(
          value.settings.auxiliary.socks_prefer_ipv6, 'SOCKS IPv6 preference state',
        ),
      },
      tlsAutodetect: safeBoolean(value.settings.tls_autodetect, 'TLS autodetection state'),
      tlsAutodetectHarder: safeBoolean(value.settings.tls_autodetect_harder, 'hard TLS autodetection state'),
      kernelTls: safeBoolean(value.settings.kernel_tls, 'kernel TLS state'),
      nameserverCount: safeInteger(value.settings.nameserver_count, 'nameserver count', MAX_REFERENCES),
      nameservers,
      httpApi: {
        keyCount: safeInteger(value.settings.http_api.key_count, 'API key count', MAX_REFERENCES),
        allowedIpCount: safeInteger(value.settings.http_api.allowed_ip_count, 'API allowed-IP count', MAX_REFERENCES),
        allowedIps,
        keyTimeout: rangedInteger(value.settings.http_api.key_timeout, 'API key timeout', 1, 4294967295),
        port: rangedInteger(value.settings.http_api.port, 'API port', 1025, 65534),
        keyExtendOnAccess: safeBoolean(
          value.settings.http_api.key_extend_on_access, 'API key extension state',
        ),
        loopbackOnly: safeBoolean(value.settings.http_api.loopback_only, 'API loopback state'),
        pamLogin: safeBoolean(value.settings.http_api.pam_login, 'API PAM state'),
        allowApiHeader: safeBoolean(value.settings.http_api.allow_api_header, 'API header state'),
        bindAddressConfigured: safeBoolean(
          value.settings.http_api.bind_address_configured, 'API bind-address state',
        ),
        bindInterfaceConfigured: safeBoolean(
          value.settings.http_api.bind_interface_configured, 'API bind-interface state',
        ),
      },
      webhook: {
        enabled: safeBoolean(value.settings.webhook.enabled, 'webhook state'),
        tlsVerify: safeBoolean(value.settings.webhook.tls_verify, 'webhook TLS verification state'),
        urlConfigured: safeBoolean(value.settings.webhook.url_configured, 'webhook URL state'),
        siftEnabled: safeBoolean(value.settings.webhook.sift_enabled, 'Sift state'),
        siftUrlConfigured: safeBoolean(
          value.settings.webhook.sift_url_configured, 'Sift URL state',
        ),
        siftTenantConfigured: safeBoolean(
          value.settings.webhook.sift_tenant_configured, 'Sift tenant state',
        ),
        siftInstanceConfigured: safeBoolean(
          value.settings.webhook.sift_instance_configured, 'Sift instance state',
        ),
        siftPayloadLimitPerDirection: rangedInteger(
          value.settings.webhook.sift_payload_limit_per_direction,
          'Sift payload limit', 1, 1073741824,
        ),
        siftLoredMode: allowedString(
          value.settings.webhook.sift_lored_mode,
          'Sift LoreD mode', ['disabled', 'optional', 'required'],
        ) as SystemSettings['webhook']['siftLoredMode'],
        siftLoredIncludeUrl: safeBoolean(
          value.settings.webhook.sift_lored_include_url, 'Sift LoreD URL disclosure state',
        ),
        hostIdConfigured: safeBoolean(value.settings.webhook.hostid_configured, 'webhook host ID state'),
        bindInterfaceConfigured: safeBoolean(
          value.settings.webhook.bind_interface_configured, 'webhook bind-interface state',
        ),
        apiOverride: safeBoolean(value.settings.webhook.api_override, 'webhook API override state'),
        pingInterval: safeInteger(value.settings.webhook.ping_interval, 'webhook ping interval', 2147483647),
        neighborUpdateInterval: safeInteger(
          value.settings.webhook.nbr_update_interval, 'neighbor update interval', 2147483647,
        ),
        neighborTagRefreshAge: safeInteger(
          value.settings.webhook.nbr_tag_refresh_age, 'neighbor tag refresh age', 2147483647,
        ),
        taskDebug: safeBoolean(value.settings.webhook.task_debug, 'webhook task debug state'),
        taskDebugDump: safeBoolean(
          value.settings.webhook.task_debug_dump, 'webhook task debug-dump state',
        ),
      },
    };
  }
  let captures: CaptureSettings | null = null;
  let debug: DebugSettings | null = null;
  if (value.debug !== null) {
    if (!isObject(value.debug)) throw new Error('Invalid debug settings.');
    const moduleOverrideCount = safeInteger(
      value.debug.module_override_count, 'debug module override count', MAX_OBJECTS,
    );
    const moduleNames = new Set<string>();
    const moduleOverrides = boundedArray(
      value.debug.module_overrides, 'debug module overrides', MAX_REFERENCES,
    ).map((item): DebugSettings['moduleOverrides'][number] => {
      if (!isObject(item)) throw new Error('Invalid debug module override.');
      const name = safeString(item.name, 'debug module name', 128);
      if (!/^[A-Za-z0-9_-]+$/u.test(name) || moduleNames.has(name)) {
        throw new Error('Invalid debug module name.');
      }
      moduleNames.add(name);
      const kind = safeString(item.kind, 'debug module kind', 16);
      if (kind === 'boolean' && typeof item.value === 'boolean') {
        return {name, kind, value: item.value};
      }
      if (kind === 'integer' && typeof item.value === 'number' && Number.isSafeInteger(item.value)) {
        return {name, kind, value: item.value};
      }
      if (kind === 'string' && typeof item.value === 'string' && item.value.length <= 32 &&
          !/[\u0000-\u001f\u007f]/u.test(item.value)) {
        return {name, kind, value: item.value};
      }
      throw new Error('Invalid debug module override.');
    });
    if (moduleOverrideCount !== moduleOverrides.length) {
      throw new Error('Invalid debug module override count.');
    }
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
      moduleOverrideCount,
      moduleOverrides,
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
        filePrefixConfigured: safeBoolean(
          value.captures.local.file_prefix_configured, 'local capture filename prefix state',
        ),
        fileSuffixConfigured: safeBoolean(
          value.captures.local.file_suffix_configured, 'local capture filename suffix state',
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
    if (!isObject(value.security_assets) || !Array.isArray(value.security_assets.certificate_authorities) ||
        value.security_assets.certificate_authorities.length > MAX_OBJECTS ||
        !Array.isArray(value.security_assets.signatures) ||
        value.security_assets.signatures.length > MAX_OBJECTS * 2) {
      throw new Error('Invalid security asset posture.');
    }
    const authorityIds = new Set<string>();
    const authorityNames = new Set<string>();
    const certificateAuthorities = value.security_assets.certificate_authorities.map(item => {
      if (!isObject(item)) throw new Error('Invalid certificate authority summary.');
      const id = safeString(item.id, 'certificate authority ID', 128);
      const name = safeString(item.name, 'certificate authority name', 128);
      if (!id || !name || authorityIds.has(id) || authorityNames.has(name)) {
        throw new Error('Invalid certificate authority identity.');
      }
      authorityIds.add(id);
      authorityNames.add(name);
      return {
        id,
        name,
        pathConfigured: safeBoolean(item.path_configured, 'certificate authority path state'),
      };
    });
    const signatureIds = new Set<string>();
    const flowIds = new Set<string>();
    const signatures = value.security_assets.signatures.map(item => {
      if (!isObject(item)) throw new Error('Invalid signature definition.');
      const id = safeString(item.id, 'signature ID', 128);
      const kind = safeString(item.kind, 'signature kind', 16);
      const side = safeString(item.side, 'signature side', 16);
      if (signatureIds.has(id) || !['starttls', 'detection'].includes(kind) ||
          !['client', 'server'].includes(side)) {
        throw new Error('Invalid signature identity.');
      }
      signatureIds.add(id);
      const flow = boundedArray(item.flow, 'signature flow', MAX_REFERENCES).map(step => {
        if (!isObject(step)) throw new Error('Invalid signature flow step.');
        const flowId = safeString(step.id, 'signature flow ID', 128);
        const flowSide = safeString(step.side, 'signature flow side', 8);
        const type = safeString(step.type, 'signature flow type', 16);
        if (flowIds.has(flowId) || !['r', 'w'].includes(flowSide) ||
            !['regex', 'simple'].includes(type)) {
          throw new Error('Invalid signature flow step.');
        }
        flowIds.add(flowId);
        return {
          id: flowId,
          side: flowSide as 'r' | 'w',
          type: type as 'regex' | 'simple',
          expressionConfigured: safeBoolean(step.expression_configured, 'signature expression state'),
          bytesStart: safeInteger(step.bytes_start, 'signature byte offset', Number.MAX_SAFE_INTEGER),
          bytesMax: safeInteger(step.bytes_max, 'signature byte window', Number.MAX_SAFE_INTEGER),
        };
      });
      if (flow.length === 0) throw new Error('Invalid signature flow.');
      return {
        id,
        kind: kind as 'starttls' | 'detection',
        category: optionalString(item.category, 'signature category'),
        name: safeString(item.name, 'signature name', 128),
        side: side as 'client' | 'server',
        severity: rangedInteger(item.severity, 'signature severity', -2147483648, 2147483647),
        group: optionalString(item.group, 'signature group'),
        enables: optionalString(item.enables, 'signature enable target'),
        engine: optionalString(item.engine, 'signature engine'),
        flow,
      };
    });
    securityAssets = {
      certificateAuthorities,
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
      signatures,
    };
    if (securityAssets.certificateAuthorityCount !== securityAssets.certificateAuthorities.length ||
        securityAssets.certificateAuthorityPathCount !==
          securityAssets.certificateAuthorities.filter(item => item.pathConfigured).length) {
      throw new Error('Invalid certificate authority posture.');
    }
    const starttlsSignatures = signatures.filter(item => item.kind === 'starttls');
    const detectionSignatures = signatures.filter(item => item.kind === 'detection');
    if (securityAssets.starttlsSignatureCount !== starttlsSignatures.length ||
        securityAssets.starttlsFlowStepCount !== starttlsSignatures.reduce((sum, item) => sum + item.flow.length, 0) ||
        securityAssets.detectionSignatureCount !== detectionSignatures.length ||
        securityAssets.detectionFlowStepCount !== detectionSignatures.reduce((sum, item) => sum + item.flow.length, 0)) {
      throw new Error('Invalid signature posture.');
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
    const rawLayers = item.layers;
    const prioritized = rawLayers.some(layer => isObject(layer) && layer.priority !== null);
    if (prioritized && rawLayers.some(layer => !isObject(layer) || layer.priority === null)) {
      throw new Error('Inconsistent augment layer priorities.');
    }
    let activeLayerCount = 0;
    let previousPriority = -1;
    const layers = rawLayers.map((layer, index) => {
      if (!isObject(layer) || typeof layer.id !== 'string' || layer.id.length === 0 ||
          layer.id.length > 128 || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(layer.id) ||
          layerIds.has(layer.id) ||
          typeof layer.active !== 'boolean' ||
          !(layer.priority === null || (typeof layer.priority === 'number' &&
            Number.isSafeInteger(layer.priority) && layer.priority >= 0))) {
        throw new Error('Invalid augment layer.');
      }
      if (typeof layer.priority === 'number') {
        if (layer.priority <= previousPriority) {
          throw new Error('Augment layer priorities must be strictly increasing.');
        }
        previousPriority = layer.priority;
      }
      layerIds.add(layer.id);
      const layerValue = configScalar(layer.value, 'augment layer value');
      if (layer.active) activeLayerCount += 1;
      if (layer.active && index !== rawLayers.length - 1) {
        throw new Error('Active augment layer must terminate the chain.');
      }
      return {id: layer.id, priority: layer.priority, value: layerValue, active: layer.active};
    });
    const persistentValue = configScalar(item.persistent_value, 'persistent value');
    const effectiveValue = configScalar(item.effective_value, 'effective value');
    if (typeof persistentValue !== typeof effectiveValue) throw new Error('Inconsistent value provenance types.');
    if (layers.some(layer => typeof layer.value !== typeof persistentValue)) {
      throw new Error('Inconsistent augment layer value types.');
    }
    if (activeLayerCount !== 1 || !Object.is(layers.at(-1)?.value, effectiveValue)) {
      throw new Error('Invalid active augment layer.');
    }
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
  readonly #pendingRequests = new Set<AbortController>();

  constructor(apiBase: string, fetchImplementation: typeof fetch = (input, init) => fetch(input, init), timeoutMs = 5000) {
    const base = normalizedPath(apiBase);
    this.#endpoint = base === '/' ? '/config/snapshot' : `${base}/config/snapshot`;
    this.#fetch = fetchImplementation;
    this.#timeoutMs = timeoutMs;
  }

  async loadSnapshot(): Promise<ConfigSnapshot> {
    const controller = new AbortController();
    this.#pendingRequests.add(controller);
    const timeout = globalThis.setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const response = await this.#fetch(this.#endpoint, {
        cache: 'no-store',
        credentials: 'same-origin',
        headers: {Accept: 'application/json'},
        redirect: 'error',
        signal: controller.signal,
      });
      if (!response.ok) throw httpStatusError(response, 'Configuration API');
      return parseConfigSnapshot(await boundedJson(response, MAX_RESPONSE_BYTES, 'Configuration'));
    } finally {
      globalThis.clearTimeout(timeout);
      this.#pendingRequests.delete(controller);
    }
  }

  cancelPendingRequests(): void {
    for (const controller of this.#pendingRequests) controller.abort();
    this.#pendingRequests.clear();
  }
}
