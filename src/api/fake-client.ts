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
      features: ['sinkhole'],
      action: 'inspect',
      nat: '', routing: '', tlsProfile: 'inspect', sshProfile: '', detectionProfile: '',
      contentProfile: '', authProfile: '', dnsProfile: '', scriptProfile: '',
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
      features: [],
      action: 'bypass',
      nat: '', routing: '', tlsProfile: '', sshProfile: '', detectionProfile: '',
      contentProfile: '', authProfile: '', dnsProfile: '', scriptProfile: '',
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
      features: [],
      action: 'block',
      nat: '', routing: '', tlsProfile: '', sshProfile: '', detectionProfile: '',
      contentProfile: '', authProfile: '', dnsProfile: '', scriptProfile: '',
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
        {id: 'routing-office', kind: 'routing-profile', name: 'office-egress'},
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
  profiles: [
    {
      id: 'tls-0', name: 'inspect', type: 'tls',
      routing: null,
      tls: {
        inspect: true, allowUntrustedIssuers: false, allowInvalidCertificates: false,
        allowSelfSigned: false, certificateTransparency: true, ocspStapling: true,
        blockAlpn: false, onlyCustomCertificates: false, noFallbackBypass: true,
        sslKeyLog: false, clientHelloTimeoutMs: 3000, handshakeTimeoutMs: 10000,
        sniBypassEntries: 0, clientCertificateAction: 'use_configured', alerts: 'all',
      },
      usedBy: [{id: 'policy-office', kind: 'policy', name: 'office'}],
    },
    {
      id: 'routing-0', name: 'main', type: 'routing',
      routing: {
        destinationAddresses: ['internet'], destinationPorts: ['https'],
        loadBalancingMethod: 'round-robin', rewriteSni: '', rewriteSniTo: '',
      },
      tls: null,
      usedBy: [],
    },
  ],
};

export class FakeConfigClient implements ConfigClient {
  async loadSnapshot(): Promise<ConfigSnapshot> {
    return structuredClone(snapshot);
  }
}
