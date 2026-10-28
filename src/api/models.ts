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
}

export interface ProtocolObject {
  id: string;
  name: string;
  number: number;
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
}

export interface ConfigClient {
  loadSnapshot(): Promise<ConfigSnapshot>;
}
