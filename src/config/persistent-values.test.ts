import {describe, expect, it} from 'vitest';
import {ConfigFixtureClient} from './persistent-values.fixture';
import {persistentConfigurationValues} from './persistent-values';

describe('persistent configuration values', () => {
  it('indexes every readable typed editor section including administrator-visible settings', async () => {
    const snapshot = await new ConfigFixtureClient().loadSnapshot();
    const values = persistentConfigurationValues(snapshot);

    expect(values.size).toBe(311);
    expect(values.get('policy.[0].src')).toEqual(['office-net']);
    expect(values.get('address_objects.[0].value')).toBe('10.20.0.0/16');
    expect(values.get('port_objects.[0].start')).toBe(443);
    expect(values.get('proto_objects.[0].id')).toBe(6);
    expect(values.get('routing.[0].dnat_address')).toEqual(['internet']);
    expect(values.get('tls_profiles.[0].allow_invalid_certs')).toBe(false);
    expect(values.get('detection_profiles.[0].mode')).toBe(1);
    expect(values.get('content_profiles.[0].content_rules.[1].replace_each_nth')).toBe(3);
    expect(values.get('ssh_profiles.[0].shell')).toBe('pass');
    expect(values.get('alg_dns_profiles.[0].randomize_id')).toBe(true);
    expect(values.get('script_profiles.[0].type')).toBe('0');
    expect(values.get('auth_profiles.[0].resolve')).toBe(true);
    expect(values.get('settings.ssl_workers')).toBe(4);
    expect(values.get('settings.extended_local_destination_protection')).toBe(true);
    expect(values.get('settings.socks.proxy_authorization')).toBe(false);
    expect(values.get('settings.http_connect.proxy_authorization')).toBe(false);
    expect(values.get('settings.nameservers')).toEqual(['192.0.2.53', '2001:db8::53']);
    expect(values.get('settings.custom_cert_fallback_dir'))
      .toBe('/var/lib/smithproxy/custom-certs');
    expect(values.get('settings.certs_ca_key_password')).toBe('private-ca-password');
    expect(values.get('settings.http_api.keys')).toEqual(['backend-secret-value']);
    expect(values.get('debug.log.proxy')).toBe(6);
    expect(values.get('captures.remote.tun_type')).toBe('gre');
    expect(values.get('captures.options.metadata')).toBe(true);
    expect(values.get('captures.options.protocol_events')).toBe(true);
    expect(values.get('tls_ca.[0].name')).toBe('default');
    expect(values.get('detection_signatures.[0].flow.[0].bytes_max')).toBe(200);

    for (const path of [
      'auth_profiles.[0].identities',
    ]) {
      expect(values.has(path), path).toBe(false);
    }
  });
});
