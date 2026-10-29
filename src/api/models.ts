export interface PolicySummary {
  id: string;
  name: string;
  protocol: string;
  sources: ReadonlyArray<ConfigReference>;
  sourcePorts: ReadonlyArray<string>;
  destinations: ReadonlyArray<ConfigReference>;
  destinationPorts: ReadonlyArray<string>;
  features: ReadonlyArray<string>;
  action: string;
  nat: string;
  routing: string;
  tlsProfile: string;
  sshProfile: string;
  detectionProfile: string;
  contentProfile: string;
  authProfile: string;
  dnsProfile: string;
  scriptProfile: string;
  enabled: boolean;
}

export interface ConfigReference {
  id: string | null;
  name: string;
}

export interface ConfigUsage {
  id: string;
  kind: 'policy' | 'routing-profile';
  name: string;
}

export interface AddressObject {
  id: string;
  name: string;
  type: 'cidr' | 'fqdn' | 'host' | 'subnet' | 'range';
  value: string;
  usedBy: ReadonlyArray<ConfigUsage>;
}

export interface PortObject {
  id: string;
  name: string;
  start: number;
  end: number;
  usedBy: ReadonlyArray<ConfigUsage>;
}

export interface ProtocolObject {
  id: string;
  name: string;
  number: number;
  usedBy: ReadonlyArray<ConfigUsage>;
}

export interface RoutingProfileDetails {
  destinationAddresses: ReadonlyArray<string>;
  destinationPorts: ReadonlyArray<string>;
  loadBalancingMethod: 'round-robin' | 'sticky-l3' | 'sticky-l4';
  rewriteSni: string;
  rewriteSniTo: string;
}

export interface TlsProfileDetails {
  inspect: boolean;
  usePfs: boolean;
  leftUsePfs: boolean;
  rightUsePfs: boolean;
  leftDisableReuse: boolean;
  rightDisableReuse: boolean;
  allowUntrustedIssuers: boolean;
  allowInvalidCertificates: boolean;
  allowSelfSigned: boolean;
  certificateTransparency: boolean;
  ocspMode: 0 | 1 | 2;
  ocspStapling: boolean;
  ocspStaplingMode: 0 | 1 | 2;
  blockAlpn: boolean;
  sniBasedCertificates: boolean;
  ipBasedCertificates: boolean;
  onlyCustomCertificates: boolean;
  noFallbackBypass: boolean;
  sniFilterUsesDnsCache: boolean;
  sniFilterUsesDnsDomainTree: boolean;
  redirectWarningPorts: ReadonlyArray<number>;
  failedCertificateReplacement: boolean;
  failedCertificateOverride: boolean;
  failedCertificateOverrideTimeout: number;
  failedCertificateOverrideTimeoutType: 0 | 1;
  sslKeyLog: boolean;
  clientHelloTimeoutMs: number;
  handshakeTimeoutMs: number;
  sniBypassEntries: number;
  clientCertificateAction: string;
  alerts: 'all' | 'unusual' | 'mute';
}

export interface DetectionProfileDetails {
  mode: 0 | 1 | 2;
  enginesEnabled: boolean;
  knowledgeBaseEnabled: boolean;
}

export interface ContentRuleSummary {
  id: string;
  matchConfigured: true;
  replacementConfigured: boolean;
  replacementHasValue: boolean;
  fillLength: boolean;
  replaceEachNth: number;
}

export interface ContentProfileDetails {
  writePayload: boolean;
  writeFormat: 'smcap' | 'pcap' | 'pcap_single';
  webhookEnabled: boolean;
  webhookLocksTraffic: boolean;
  ja4TlsClientHello: boolean;
  ja4TlsClientHelloIgnoresSni: boolean;
  ja4TlsServerHello: boolean;
  ja4Http: boolean;
  sessionFilterConfigured: boolean;
  ruleCount: number;
  rules: ReadonlyArray<ContentRuleSummary>;
}

export interface SshProfileDetails {
  hostKeyConfigured: boolean;
  hostKeyPolicy: 'insecure' | 'accept-new' | 'strict';
  shell: boolean;
  exec: boolean;
  subsystem: boolean;
  pty: boolean;
  environment: boolean;
  localForward: boolean;
  remoteForward: boolean;
  x11: boolean;
  agent: boolean;
}

export interface DnsProfileDetails {
  matchRequestId: boolean;
  randomizeId: boolean;
  cachedResponses: boolean;
}

export interface ScriptProfileDetails {
  runtime: 'python' | 'go' | 'unknown';
  modulePathConfigured: boolean;
}

export interface AuthenticationProfileDetails {
  authenticate: boolean;
  resolve: boolean;
  identityCount: number;
  deprecated: true;
}

export interface ProfileObject {
  id: string;
  name: string;
  type: string;
  routing: RoutingProfileDetails | null;
  tls: TlsProfileDetails | null;
  detection: DetectionProfileDetails | null;
  content: ContentProfileDetails | null;
  ssh: SshProfileDetails | null;
  dns: DnsProfileDetails | null;
  script: ScriptProfileDetails | null;
  authentication: AuthenticationProfileDetails | null;
  usedBy: ReadonlyArray<ConfigUsage>;
}

export interface SystemSettings {
  acceptTproxy: boolean;
  acceptRedirect: boolean;
  acceptSocks: boolean;
  acceptHttpConnect: boolean;
  acceptApi: boolean;
  extendedLocalDestinationProtection: boolean;
  policyFailOpen: boolean;
  accessRequestFailOpen: boolean;
  workers: Readonly<Record<'plaintext' | 'tls' | 'udp' | 'dtls' | 'quic' | 'socks' | 'httpConnect', number>>;
  ports: Readonly<Record<'plaintext' | 'tls' | 'udp' | 'dtls' | 'quic' | 'socks' | 'httpConnect', number>>;
  ocspStatusTtl: number;
  crlStatusTtl: number;
  logging: {
    defaultWritePayload: boolean;
    payloadDirectoryConfigured: boolean;
    pcapSingleQuota: number;
    level: number;
    fileConfigured: boolean;
    console: boolean;
    sslKeyFileConfigured: boolean;
    syslogServerConfigured: boolean;
    syslogPort: number;
    syslogFacility: number;
    syslogLevel: number;
    syslogFamily: 4 | 6;
  };
  auxiliary: {
    udpQuickPortCount: number;
    udpQuickPorts: ReadonlyArray<string>;
    certificatesPathConfigured: boolean;
    certificatePasswordConfigured: boolean;
    certificateTransparencyLogConfigured: boolean;
    caBundlePathConfigured: boolean;
    caBundleFileConfigured: boolean;
    messagesDirectoryConfigured: boolean;
    payloadFilePrefixConfigured: boolean;
    payloadFileSuffixConfigured: boolean;
    cliPort: number;
    cliPasswordConfigured: boolean;
    webRatingKeyConfigured: boolean;
    adminGroupConfigured: boolean;
    tuning: {
      hostBufferMin: number;
      hostBufferMaxMultiplier: number;
      hostWriteFull: number;
      hostIoBatch: number;
      tlsWriteChunk: number;
      hostOpenTimeout: number;
      hostIdleTimeout: number;
      neighborCacheSize: number;
    };
    threadPoolLogging: boolean;
    socksAsyncDns: boolean;
    socksIpVersionMixing: boolean;
    socksPreferIpv6: boolean;
  };
  tlsAutodetect: boolean;
  tlsAutodetectHarder: boolean;
  kernelTls: boolean;
  nameserverCount: number;
  nameservers: ReadonlyArray<string>;
  httpApi: {
    keyCount: number;
    allowedIpCount: number;
    allowedIps: ReadonlyArray<string>;
    keyTimeout: number;
    port: number;
    keyExtendOnAccess: boolean;
    loopbackOnly: boolean;
    pamLogin: boolean;
    allowApiHeader: boolean;
    bindAddressConfigured: boolean;
    bindInterfaceConfigured: boolean;
  };
  webhook: {
    enabled: boolean;
    tlsVerify: boolean;
    urlConfigured: boolean;
    siftEnabled: boolean;
    siftUrlConfigured: boolean;
    siftTenantConfigured: boolean;
    siftInstanceConfigured: boolean;
    siftPayloadLimitPerDirection: number;
    siftLoredMode: 'disabled' | 'optional' | 'required';
    siftLoredIncludeUrl: boolean;
    hostIdConfigured: boolean;
    bindInterfaceConfigured: boolean;
    apiOverride: boolean;
    pingInterval: number;
    neighborUpdateInterval: number;
    neighborTagRefreshAge: number;
    taskDebug: boolean;
    taskDebugDump: boolean;
  };
}

export interface CaptureSettings {
  local: {
    enabled: boolean;
    directoryConfigured: boolean;
    filePrefixConfigured: boolean;
    fileSuffixConfigured: boolean;
    format: 'pcap_single' | 'pcap' | 'smcap';
    quotaMiB: number;
  };
  remote: {
    enabled: boolean;
    tunnelType: 'gre';
    greFormat: 'traffic' | 'pcapng';
    destinationConfigured: boolean;
    ttl: number;
    bindInterfaceConfigured: boolean;
  };
  calculateChecksums: boolean;
}

export interface DebugSettings {
  logDataCrc: boolean;
  logSockets: boolean;
  logOnlineConnectionName: boolean;
  logSourceLines: boolean;
  logSourceLinesAlways: boolean;
  moduleOverrideCount: number;
  moduleOverrides: ReadonlyArray<{
    name: string;
    kind: 'boolean' | 'integer' | 'string';
    value: boolean | number | string;
  }>;
}

export interface CertificateAuthoritySummary {
  id: string;
  name: string;
  pathConfigured: boolean;
}

export interface SignatureFlowStep {
  id: string;
  side: 'r' | 'w';
  type: 'regex' | 'simple';
  expressionConfigured: boolean;
  bytesStart: number;
  bytesMax: number;
}

export interface SignatureDefinition {
  id: string;
  kind: 'starttls' | 'detection';
  category: string;
  name: string;
  side: 'client' | 'server';
  severity: number;
  group: string;
  enables: string;
  engine: string;
  flow: ReadonlyArray<SignatureFlowStep>;
}

export interface SecurityAssets {
  certificateAuthorities: ReadonlyArray<CertificateAuthoritySummary>;
  certificateAuthorityCount: number;
  certificateAuthorityPathCount: number;
  starttlsSignatureCount: number;
  starttlsFlowStepCount: number;
  detectionSignatureCount: number;
  detectionFlowStepCount: number;
  signatures: ReadonlyArray<SignatureDefinition>;
}

export type ConfigScalar = boolean | number | string;
export type ConfigValue = ConfigScalar | ReadonlyArray<string> | ReadonlyArray<number>;

export interface AugmentLayer {
  id: string;
  priority: number | null;
  value: ConfigValue;
  active: boolean;
}

export interface ValueOrigin {
  path: string;
  persistentValue: ConfigValue;
  effectiveValue: ConfigValue;
  layers: ReadonlyArray<AugmentLayer>;
  editable: boolean;
}

export interface ConfigSnapshot {
  source: 'preview' | 'live';
  state: 'ready' | 'starting' | 'unavailable' | 'unconfigured';
  detail: string;
  checkedAtUnixMs: number | null;
  lastSuccessAtUnixMs: number | null;
  revision: string | null;
  policies: ReadonlyArray<PolicySummary>;
  addresses: ReadonlyArray<AddressObject>;
  ports: ReadonlyArray<PortObject>;
  protocols: ReadonlyArray<ProtocolObject>;
  profiles: ReadonlyArray<ProfileObject>;
  settings: SystemSettings | null;
  debug: DebugSettings | null;
  captures: CaptureSettings | null;
  securityAssets: SecurityAssets | null;
  augmentSupport: boolean;
  valueOrigins: ReadonlyArray<ValueOrigin>;
}

export interface ConfigClient {
  loadSnapshot(): Promise<ConfigSnapshot>;
}
