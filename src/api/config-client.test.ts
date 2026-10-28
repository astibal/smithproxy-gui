import {describe, expect, it, vi} from 'vitest';
import {ApiConfigClient, parseConfigSnapshot} from './config-client';

const liveSnapshot = {
  state: 'ready',
  detail: 'Current runtime configuration',
  checked_at_unix_ms: 100,
  last_success_at_unix_ms: 100,
  view: 'runtime',
  revision: null,
  policies: [{
    id: 'policy-0', name: 'Policy 1', enabled: true, protocol: 'tcp', sources: ['office'],
    source_ports: ['any'], destinations: ['internet'], destination_ports: ['https'],
    features: ['sinkhole'],
    action: 'accept', nat: '', routing: 'main', tls_profile: 'inspect',
    ssh_profile: '', detection_profile: '', content_profile: '', auth_profile: '',
    dns_profile: '', script_profile: '',
  }],
  addresses: [
    {id: 'address-0', name: 'office', type: 'cidr', value: '10.0.0.0/24'},
    {id: 'address-1', name: 'internet', type: 'fqdn', value: 'example.test'},
  ],
  ports: [{id: 'port-0', name: 'https', start: 443, end: 443}],
  protocols: [{id: 'protocol-0', name: 'tcp', number: 6}],
  profiles: [
    {id: 'tls-0', name: 'inspect', type: 'tls', routing: null},
    {
      id: 'routing-0', name: 'main', type: 'routing',
      routing: {
        destination_addresses: ['internet'], destination_ports: ['https'],
        load_balancing_method: 'sticky-l3', rewrite_sni: 'old.example', rewrite_sni_to: 'new.example',
      },
    },
  ],
};

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {status, headers: {'Content-Type': 'application/json'}});
}

describe('ApiConfigClient', () => {
  it('maps the bounded runtime snapshot and derives object impact', async () => {
    const fetcher = vi.fn(async () => response(liveSnapshot));
    const client = new ApiConfigClient('/ws001/smithproxy-gui/api/v1/', fetcher);
    const snapshot = await client.loadSnapshot();

    expect(snapshot).toMatchObject({source: 'live', state: 'ready', revision: null});
    expect(snapshot.policies[0]).toMatchObject({
      protocol: 'tcp', action: 'accept',
      sources: [{id: 'address-0', name: 'office'}],
    });
    expect(snapshot.addresses[0]?.usedBy).toEqual([
      {id: 'policy-0', kind: 'policy', name: 'Policy 1'},
    ]);
    expect(snapshot.ports[0]).toMatchObject({start: 443, end: 443});
    expect(snapshot.ports[0]?.usedBy).toEqual([
      {id: 'policy-0', kind: 'policy', name: 'Policy 1'},
      {id: 'routing-0', kind: 'routing-profile', name: 'main'},
    ]);
    expect(snapshot.protocols[0]?.usedBy).toEqual([{id: 'policy-0', kind: 'policy', name: 'Policy 1'}]);
    expect(snapshot.profiles.map(item => item.usedBy.length)).toEqual([1, 1]);
    expect(snapshot.profiles[1]?.routing).toMatchObject({loadBalancingMethod: 'sticky-l3'});
    expect(snapshot.addresses[1]?.usedBy).toContainEqual({id: 'routing-0', kind: 'routing-profile', name: 'main'});
    expect(snapshot.ports[0]?.usedBy).toContainEqual({id: 'routing-0', kind: 'routing-profile', name: 'main'});
    expect(fetcher).toHaveBeenCalledWith(
      '/ws001/smithproxy-gui/api/v1/config/snapshot',
      expect.objectContaining({cache: 'no-store', credentials: 'same-origin', redirect: 'error'}),
    );
  });

  it('rejects malformed collections, unsafe paths, and non-success responses', async () => {
    expect(() => new ApiConfigClient('https://other.example/api')).toThrow('same-origin');
    expect(() => new ApiConfigClient('/api/../secret')).toThrow('relative path');
    expect(() => parseConfigSnapshot({...liveSnapshot, addresses: [
      liveSnapshot.addresses[0], {...liveSnapshot.addresses[0], id: 'address-2'},
    ]})).toThrow('Duplicate address object');
    expect(() => parseConfigSnapshot({...liveSnapshot, ports: [
      {id: 'bad', name: 'bad', start: 10, end: 1},
    ]})).toThrow('Invalid port range');
    expect(() => parseConfigSnapshot({...liveSnapshot, state: {toString: () => 'ready'}}))
      .toThrow('Invalid configuration snapshot');

    const client = new ApiConfigClient('/api/v1', async () => response({}, 401));
    await expect(client.loadSnapshot()).rejects.toThrow('HTTP 401');

    const oversized = new ApiConfigClient('/api/v1', async () => new Response('{}', {
      headers: {'Content-Length': String(4 * 1024 * 1024 + 1)},
    }));
    await expect(oversized.loadSnapshot()).rejects.toThrow('size limit');
  });
});
