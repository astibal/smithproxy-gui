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

export interface ProfileObject {
  id: string;
  name: string;
  type: string;
  routing: RoutingProfileDetails | null;
  tls: TlsProfileDetails | null;
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
