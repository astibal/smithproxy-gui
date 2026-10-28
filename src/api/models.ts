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
  allowUntrustedIssuers: boolean;
  allowInvalidCertificates: boolean;
  allowSelfSigned: boolean;
  certificateTransparency: boolean;
  ocspStapling: boolean;
  blockAlpn: boolean;
  onlyCustomCertificates: boolean;
  noFallbackBypass: boolean;
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
}

export interface ConfigClient {
  loadSnapshot(): Promise<ConfigSnapshot>;
}
