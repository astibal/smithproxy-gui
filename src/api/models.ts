export interface PolicySummary {
  id: string;
  name: string;
  protocol: string;
  sources: ReadonlyArray<ConfigReference>;
  sourcePorts: ReadonlyArray<string>;
  destinations: ReadonlyArray<ConfigReference>;
  destinationPorts: ReadonlyArray<string>;
  action: string;
  nat: string;
  routing: string;
  tlsProfile: string;
  enabled: boolean;
}

export interface ConfigReference {
  id: string | null;
  name: string;
}

export interface AddressObject {
  id: string;
  name: string;
  type: 'cidr' | 'fqdn' | 'host' | 'subnet' | 'range';
  value: string;
  usedBy: ReadonlyArray<{id: string; kind: 'policy' | 'routing-rule'; name: string}>;
}

export interface PortObject {
  id: string;
  name: string;
  start: number;
  end: number;
  usedBy: ReadonlyArray<{id: string; kind: 'policy'; name: string}>;
}

export interface ProtocolObject {
  id: string;
  name: string;
  number: number;
  usedBy: ReadonlyArray<{id: string; kind: 'policy'; name: string}>;
}

export interface ProfileObject {
  id: string;
  name: string;
  type: string;
  usedBy: ReadonlyArray<{id: string; kind: 'policy'; name: string}>;
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
