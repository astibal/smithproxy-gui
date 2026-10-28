export interface PolicySummary {
  id: string;
  name: string;
  sourceId: string;
  sourceName: string;
  destinationName: string;
  action: 'inspect' | 'bypass' | 'block';
  enabled: boolean;
}
export interface AddressObject {
  id: string;
  name: string;
  type: 'host' | 'subnet' | 'range';
  value: string;
  usedBy: ReadonlyArray<{id: string; kind: 'policy' | 'routing-rule'; name: string}>;
}

export interface ConfigSnapshot {
  revision: string;
  policies: ReadonlyArray<PolicySummary>;
  addresses: ReadonlyArray<AddressObject>;
}

export interface ConfigClient {
  loadSnapshot(): Promise<ConfigSnapshot>;
}
