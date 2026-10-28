import type {ConfigClient, ConfigSnapshot} from './models';

const snapshot: ConfigSnapshot = {
  source: 'preview',
  state: 'ready',
  detail: 'Preview configuration data',
  checkedAtUnixMs: null,
  lastSuccessAtUnixMs: null,
  revision: 'preview-1',
  policies: [
    {
      id: 'policy-office',
      name: 'office',
      protocol: 'tcp',
      sources: [{id: 'address-office-net', name: 'office-net'}],
      sourcePorts: ['any'],
      destinations: [{id: null, name: 'internet'}],
      destinationPorts: ['https'],
      action: 'inspect',
      nat: '', routing: '', tlsProfile: 'inspect',
      enabled: true,
    },
    {
      id: 'policy-guest',
      name: 'guest',
      protocol: 'tcp',
      sources: [{id: 'address-guest-net', name: 'guest-net'}],
      sourcePorts: ['any'],
      destinations: [{id: null, name: 'internet'}],
      destinationPorts: ['any'],
      action: 'bypass',
      nat: '', routing: '', tlsProfile: '',
      enabled: true,
    },
    {
      id: 'policy-quarantine',
      name: 'quarantine',
      protocol: 'tcp',
      sources: [{id: 'address-quarantine', name: 'quarantine-net'}],
      sourcePorts: ['any'],
      destinations: [{id: null, name: 'any'}],
      destinationPorts: ['any'],
      action: 'block',
      nat: '', routing: '', tlsProfile: '',
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
  ports: [{
    id: 'port-https', name: 'https', start: 443, end: 443,
    usedBy: [{id: 'policy-office', kind: 'policy', name: 'office'}],
  }],
  protocols: [{
    id: 'protocol-tcp', name: 'tcp', number: 6,
    usedBy: [
      {id: 'policy-office', kind: 'policy', name: 'office'},
      {id: 'policy-guest', kind: 'policy', name: 'guest'},
      {id: 'policy-quarantine', kind: 'policy', name: 'quarantine'},
    ],
  }],
};

export class FakeConfigClient implements ConfigClient {
  async loadSnapshot(): Promise<ConfigSnapshot> {
    return structuredClone(snapshot);
  }
}
