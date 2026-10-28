import type {ConfigClient, ConfigSnapshot} from './models';

const snapshot: ConfigSnapshot = {
  revision: 'demo-1',
  policies: [
    {
      id: 'policy-office',
      name: 'office',
      sourceId: 'address-office-net',
      sourceName: 'office-net',
      destinationName: 'internet',
      action: 'inspect',
      enabled: true,
    },
    {
      id: 'policy-guest',
      name: 'guest',
      sourceId: 'address-guest-net',
      sourceName: 'guest-net',
      destinationName: 'internet',
      action: 'bypass',
      enabled: true,
    },
    {
      id: 'policy-quarantine',
      name: 'quarantine',
      sourceId: 'address-quarantine',
      sourceName: 'quarantine-net',
      destinationName: 'any',
      action: 'block',
      enabled: false,
    },
  ],
  addresses: [
    {
      id: 'address-office-net',
      name: 'office-net',
      type: 'subnet',
      value: '10.20.0.0/16',
      usedBy: [
        {id: 'policy-office', kind: 'policy', name: 'office'},
        {id: 'policy-admin', kind: 'policy', name: 'admin'},
        {id: 'policy-vpn', kind: 'policy', name: 'vpn'},
        {id: 'routing-office', kind: 'routing-rule', name: 'office-egress'},
      ],
    },
    {
      id: 'address-guest-net',
      name: 'guest-net',
      type: 'subnet',
      value: '10.80.0.0/16',
      usedBy: [{id: 'policy-guest', kind: 'policy', name: 'guest'}],
    },
    {
      id: 'address-quarantine',
      name: 'quarantine-net',
      type: 'subnet',
      value: '10.99.0.0/16',
      usedBy: [{id: 'policy-quarantine', kind: 'policy', name: 'quarantine'}],
    },
  ],
};

export class FakeConfigClient implements ConfigClient {
  async loadSnapshot(): Promise<ConfigSnapshot> {
    return structuredClone(snapshot);
  }
}
