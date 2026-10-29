import type {ConfigSnapshot, ConfigValue, ProfileObject} from '../api/models';

export function persistentConfigurationValues(snapshot: ConfigSnapshot): ReadonlyMap<string, ConfigValue> {
  const values = new Map<string, ConfigValue>();
  const set = (path: string, value: ConfigValue) => values.set(path, value);

  for (const [index, policy] of snapshot.policies.entries()) {
    const base = `policy.[${index}]`;
    set(`${base}.name`, policy.name);
    set(`${base}.disabled`, !policy.enabled);
    set(`${base}.proto`, policy.protocol);
    set(`${base}.src`, policy.sources.map(item => item.name));
    set(`${base}.sport`, policy.sourcePorts);
    set(`${base}.dst`, policy.destinations.map(item => item.name));
    set(`${base}.dport`, policy.destinationPorts);
    set(`${base}.features`, policy.features);
    set(`${base}.action`, policy.action);
    set(`${base}.nat`, policy.nat);
    set(`${base}.routing`, policy.routing);
    set(`${base}.tls_profile`, policy.tlsProfile);
    set(`${base}.ssh_profile`, policy.sshProfile);
    set(`${base}.detection_profile`, policy.detectionProfile);
    set(`${base}.content_profile`, policy.contentProfile);
    set(`${base}.auth_profile`, policy.authProfile);
    set(`${base}.alg_dns_profile`, policy.dnsProfile);
    set(`${base}.script_profile`, policy.scriptProfile);
  }
  snapshot.addresses.forEach((item, index) => {
    const base = `address_objects.[${index}]`;
    set(`${base}.name`, item.name);
    set(`${base}.type`, item.type);
    set(`${base}.value`, item.value);
  });
  snapshot.ports.forEach((item, index) => {
    const base = `port_objects.[${index}]`;
    set(`${base}.name`, item.name);
    set(`${base}.start`, item.start);
    set(`${base}.end`, item.end);
  });
  snapshot.protocols.forEach((item, index) => {
    const base = `proto_objects.[${index}]`;
    set(`${base}.name`, item.name);
    set(`${base}.id`, item.number);
  });

  const profiles = (select: (item: ProfileObject) => boolean) => snapshot.profiles.filter(select);
  profiles(item => item.routing !== null).forEach((item, index) => {
    const base = `routing.[${index}]`;
    const profile = item.routing!;
    set(`${base}.name`, item.name);
    set(`${base}.dnat_address`, profile.destinationAddresses);
    set(`${base}.dnat_port`, profile.destinationPorts);
    set(`${base}.dnat_lb_method`, profile.loadBalancingMethod);
    set(`${base}.rewrite_sni`, profile.rewriteSni);
    set(`${base}.rewrite_sni_to`, profile.rewriteSniTo);
  });
  profiles(item => item.tls !== null).forEach((item, index) => {
    const base = `tls_profiles.[${index}]`;
    const profile = item.tls!;
    set(`${base}.name`, item.name);
    set(`${base}.inspect`, profile.inspect);
    set(`${base}.use_pfs`, profile.usePfs);
    set(`${base}.left_use_pfs`, profile.leftUsePfs);
    set(`${base}.right_use_pfs`, profile.rightUsePfs);
    set(`${base}.left_disable_reuse`, profile.leftDisableReuse);
    set(`${base}.right_disable_reuse`, profile.rightDisableReuse);
    set(`${base}.allow_untrusted_issuers`, profile.allowUntrustedIssuers);
    set(`${base}.allow_invalid_certs`, profile.allowInvalidCertificates);
    set(`${base}.allow_self_signed`, profile.allowSelfSigned);
    set(`${base}.ct_enable`, profile.certificateTransparency);
    set(`${base}.ocsp_mode`, profile.ocspMode);
    set(`${base}.ocsp_stapling`, profile.ocspStapling);
    set(`${base}.ocsp_stapling_mode`, profile.ocspStaplingMode);
    set(`${base}.alpn_block`, profile.blockAlpn);
    set(`${base}.sni_based_cert`, profile.sniBasedCertificates);
    set(`${base}.ip_based_cert`, profile.ipBasedCertificates);
    set(`${base}.only_custom_certs`, profile.onlyCustomCertificates);
    set(`${base}.no_fallback_bypass`, profile.noFallbackBypass);
    set(`${base}.sni_filter_use_dns_cache`, profile.sniFilterUsesDnsCache);
    set(`${base}.sni_filter_use_dns_domain_tree`, profile.sniFilterUsesDnsDomainTree);
    set(`${base}.redirect_warning_ports`, profile.redirectWarningPorts);
    set(`${base}.failed_certcheck_replacement`, profile.failedCertificateReplacement);
    set(`${base}.failed_certcheck_override`, profile.failedCertificateOverride);
    set(`${base}.failed_certcheck_override_timeout`, profile.failedCertificateOverrideTimeout);
    set(`${base}.failed_certcheck_override_timeout_type`, profile.failedCertificateOverrideTimeoutType);
    set(`${base}.sslkeylog`, profile.sslKeyLog);
    set(`${base}.client_hello_timeout`, profile.clientHelloTimeoutMs);
    set(`${base}.handshake_timeout`, profile.handshakeTimeoutMs);
    set(`${base}.client_cert_action`, profile.clientCertificateAction);
    set(`${base}.alerts`, profile.alerts);
  });
  profiles(item => item.detection !== null).forEach((item, index) => {
    const base = `detection_profiles.[${index}]`;
    const profile = item.detection!;
    set(`${base}.name`, item.name);
    set(`${base}.mode`, profile.mode);
    set(`${base}.engines_enabled`, profile.enginesEnabled);
    set(`${base}.kb_enabled`, profile.knowledgeBaseEnabled);
  });
  profiles(item => item.content !== null).forEach((item, index) => {
    const base = `content_profiles.[${index}]`;
    const profile = item.content!;
    set(`${base}.name`, item.name);
    set(`${base}.write_payload`, profile.writePayload);
    set(`${base}.write_format`, profile.writeFormat);
    set(`${base}.webhook_enable`, profile.webhookEnabled);
    set(`${base}.webhook_lock_traffic`, profile.webhookLocksTraffic);
    set(`${base}.ja4_tls_ch`, profile.ja4TlsClientHello);
    set(`${base}.ja4_tls_ch_ignore_sni`, profile.ja4TlsClientHelloIgnoresSni);
    set(`${base}.ja4_tls_sh`, profile.ja4TlsServerHello);
    set(`${base}.ja4_http`, profile.ja4Http);
    profile.rules.forEach((rule, ruleIndex) => {
      const ruleBase = `${base}.content_rules.[${ruleIndex}]`;
      set(`${ruleBase}.fill_length`, rule.fillLength);
      set(`${ruleBase}.replace_each_nth`, rule.replaceEachNth);
    });
  });
  profiles(item => item.ssh !== null).forEach((item, index) => {
    const base = `ssh_profiles.[${index}]`;
    const profile = item.ssh!;
    set(`${base}.name`, item.name);
    set(`${base}.hostkey_policy`, profile.hostKeyPolicy);
    set(`${base}.shell`, profile.shell ? 'pass' : 'reject');
    set(`${base}.exec`, profile.exec ? 'pass' : 'reject');
    set(`${base}.subsystem`, profile.subsystem ? 'pass' : 'reject');
    set(`${base}.pty`, profile.pty ? 'pass' : 'reject');
    set(`${base}.environment`, profile.environment ? 'pass' : 'reject');
    set(`${base}.local_forward`, profile.localForward ? 'pass' : 'reject');
    set(`${base}.remote_forward`, profile.remoteForward ? 'pass' : 'reject');
    set(`${base}.x11`, profile.x11 ? 'pass' : 'reject');
    set(`${base}.agent`, profile.agent ? 'pass' : 'reject');
  });
  profiles(item => item.dns !== null).forEach((item, index) => {
    const base = `alg_dns_profiles.[${index}]`;
    const profile = item.dns!;
    set(`${base}.name`, item.name);
    set(`${base}.match_request_id`, profile.matchRequestId);
    set(`${base}.randomize_id`, profile.randomizeId);
    set(`${base}.cached_responses`, profile.cachedResponses);
  });
  profiles(item => item.script !== null).forEach((item, index) => {
    const base = `script_profiles.[${index}]`;
    const profile = item.script!;
    set(`${base}.name`, item.name);
    set(`${base}.type`, profile.runtime === 'python' ? '0' : profile.runtime === 'go' ? '1' : '-1');
  });
  profiles(item => item.authentication !== null).forEach((item, index) => {
    const base = `auth_profiles.[${index}]`;
    const profile = item.authentication!;
    set(`${base}.name`, item.name);
    set(`${base}.authenticate`, profile.authenticate);
    set(`${base}.resolve`, profile.resolve);
  });

  const settings = snapshot.settings;
  if (settings) {
    const base = 'settings.';
    const fields: ReadonlyArray<readonly [string, ConfigValue]> = [
      ['accept_tproxy', settings.acceptTproxy], ['accept_redirect', settings.acceptRedirect],
      ['accept_socks', settings.acceptSocks], ['accept_http_connect', settings.acceptHttpConnect],
      ['accept_api', settings.acceptApi],
      ['policy_fail_open', settings.policyFailOpen],
      ['policy_access_request_fail_open', settings.accessRequestFailOpen],
      ['plaintext_workers', settings.workers.plaintext], ['ssl_workers', settings.workers.tls],
      ['udp_workers', settings.workers.udp], ['dtls_workers', settings.workers.dtls],
      ['quic_workers', settings.workers.quic], ['socks_workers', settings.workers.socks],
      ['http_connect_workers', settings.workers.httpConnect],
      ['plaintext_port', settings.ports.plaintext], ['ssl_port', settings.ports.tls],
      ['udp_port', settings.ports.udp], ['dtls_port', settings.ports.dtls],
      ['quic_port', settings.ports.quic], ['socks_port', settings.ports.socks],
      ['http_connect_port', settings.ports.httpConnect],
      ['ssl_ocsp_status_ttl', settings.ocspStatusTtl], ['ssl_crl_status_ttl', settings.crlStatusTtl],
      ['default_write_payload', settings.logging.defaultWritePayload],
      ['write_pcap_single_quota', settings.logging.pcapSingleQuota],
      ['log_level', settings.logging.level], ['log_console', settings.logging.console],
      ['syslog_port', settings.logging.syslogPort], ['syslog_facility', settings.logging.syslogFacility],
      ['syslog_level', settings.logging.syslogLevel], ['syslog_family', settings.logging.syslogFamily],
      ['udp_quick_ports', settings.auxiliary.udpQuickPorts], ['cli.port', settings.auxiliary.cliPort],
      ['tpool_log', settings.auxiliary.threadPoolLogging],
      ['socks.async_dns', settings.auxiliary.socksAsyncDns],
      ['socks.ipver_mixing', settings.auxiliary.socksIpVersionMixing],
      ['socks.prefer_ipv6', settings.auxiliary.socksPreferIpv6],
      ['tuning.host_bufsz_min', settings.auxiliary.tuning.hostBufferMin],
      ['tuning.host_bufsz_max_multiplier', settings.auxiliary.tuning.hostBufferMaxMultiplier],
      ['tuning.host_write_full', settings.auxiliary.tuning.hostWriteFull],
      ['tuning.host_io_batch', settings.auxiliary.tuning.hostIoBatch],
      ['tuning.tls_write_chunk', settings.auxiliary.tuning.tlsWriteChunk],
      ['tuning.host_open_timeout', settings.auxiliary.tuning.hostOpenTimeout],
      ['tuning.host_idle_timeout', settings.auxiliary.tuning.hostIdleTimeout],
      ['tuning.nbr_cache_size', settings.auxiliary.tuning.neighborCacheSize],
      ['ssl_autodetect', settings.tlsAutodetect], ['ssl_autodetect_harder', settings.tlsAutodetectHarder],
      ['ssl_use_ktls', settings.kernelTls], ['nameservers', settings.nameservers],
      ['http_api.allowed_ips', settings.httpApi.allowedIps],
      ['http_api.key_timeout', settings.httpApi.keyTimeout], ['http_api.port', settings.httpApi.port],
      ['http_api.key_extend_on_access', settings.httpApi.keyExtendOnAccess],
      ['http_api.loopback_only', settings.httpApi.loopbackOnly],
      ['http_api.pam_login', settings.httpApi.pamLogin],
      ['http_api.allow_api_header', settings.httpApi.allowApiHeader],
      ['webhook.enabled', settings.webhook.enabled], ['webhook.tls_verify', settings.webhook.tlsVerify],
      ['webhook.sift', settings.webhook.siftEnabled], ['webhook.api_override', settings.webhook.apiOverride],
      ['webhook.sift_payload_limit_per_direction', settings.webhook.siftPayloadLimitPerDirection],
      ['webhook.ping_interval', settings.webhook.pingInterval],
      ['webhook.nbr_update_interval', settings.webhook.neighborUpdateInterval],
      ['webhook.nbr_tag_refresh_age', settings.webhook.neighborTagRefreshAge],
      ['webhook.task_debug', settings.webhook.taskDebug],
      ['webhook.task_debug_dump', settings.webhook.taskDebugDump],
    ];
    fields.forEach(([path, value]) => set(`${base}${path}`, value));
  }
  if (snapshot.debug) {
    set('debug.log_data_crc', snapshot.debug.logDataCrc);
    set('debug.log_sockets', snapshot.debug.logSockets);
    set('debug.log_online_cx_name', snapshot.debug.logOnlineConnectionName);
    set('debug.log_srclines', snapshot.debug.logSourceLines);
    set('debug.log_srclines_always', snapshot.debug.logSourceLinesAlways);
    snapshot.debug.moduleOverrides.forEach(item => set(`debug.log.${item.name}`, item.value));
  }
  if (snapshot.captures) {
    const capture = snapshot.captures;
    set('captures.local.enabled', capture.local.enabled);
    set('captures.local.pcap_quota', capture.local.quotaMiB);
    set('captures.local.format', capture.local.format);
    set('captures.remote.enabled', capture.remote.enabled);
    set('captures.remote.tun_type', capture.remote.tunnelType);
    set('captures.remote.gre_format', capture.remote.greFormat);
    set('captures.remote.tun_ttl', capture.remote.ttl);
    set('captures.options.calculate_checksums', capture.calculateChecksums);
  }
  if (snapshot.securityAssets) {
    snapshot.securityAssets.certificateAuthorities.forEach((item, index) =>
      set(`tls_ca.[${index}].name`, item.name));
    for (const kind of ['starttls', 'detection'] as const) {
      snapshot.securityAssets.signatures.filter(item => item.kind === kind).forEach((item, index) => {
        const base = `${kind}_signatures.[${index}]`;
        set(`${base}.cat`, item.category);
        set(`${base}.name`, item.name);
        set(`${base}.side`, item.side);
        set(`${base}.severity`, item.severity);
        set(`${base}.group`, item.group);
        set(`${base}.enables`, item.enables);
        set(`${base}.engine`, item.engine);
        item.flow.forEach((flow, flowIndex) => {
          const flowBase = `${base}.flow.[${flowIndex}]`;
          set(`${flowBase}.side`, flow.side);
          set(`${flowBase}.type`, flow.type);
          set(`${flowBase}.bytes_start`, flow.bytesStart);
          set(`${flowBase}.bytes_max`, flow.bytesMax);
        });
      });
    }
  }
  return values;
}
