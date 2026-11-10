import {describe, expect, it} from 'vitest';
import {describeCidr, normalizeCidr, parseCidr} from './cidr';

describe('CIDR insights', () => {
  it('describes canonical IPv4 ranges', () => {
    expect(parseCidr('192.0.2.37/24')).toEqual({
      family: 'IPv4', prefix: 24, network: '192.0.2.0', last: '192.0.2.255', addressCount: 256n,
    });
    expect(describeCidr('192.0.2.37/24'))
      .toBe('IPv4 /24 · 256 addresses · 192.0.2.0 – 192.0.2.255');
    expect(describeCidr('0.0.0.0/0'))
      .toBe('IPv4 /0 · all IPv4 addresses · 0.0.0.0 – 255.255.255.255');
  });

  it('describes compressed IPv6 ranges without expanding their size', () => {
    expect(parseCidr('2001:db8:abcd:1234::42/64')).toMatchObject({
      family: 'IPv6', prefix: 64, network: '2001:db8:abcd:1234::', last: '2001:db8:abcd:1234:ffff:ffff:ffff:ffff',
    });
    expect(describeCidr('2001:db8:abcd:1234::42/64'))
      .toBe('IPv6 /64 · 2^64 addresses · 2001:db8:abcd:1234:: – 2001:db8:abcd:1234:ffff:ffff:ffff:ffff');
  });

  it('treats bare IP literals as single-address prefixes', () => {
    expect(normalizeCidr('192.0.2.37')).toBe('192.0.2.37/32');
    expect(describeCidr('192.0.2.37'))
      .toBe('IPv4 /32 · single address · 192.0.2.37');
    expect(normalizeCidr('2001:db8::42')).toBe('2001:db8::42/128');
    expect(describeCidr('2001:db8::42'))
      .toBe('IPv6 /128 · single address · 2001:db8::42');
  });

  it.each(['192.0.2.01', '192.0.2.01/24', '192.0.2.256/24', '2001:::1/64', '2001:db8::/129']) (
    'rejects invalid CIDR %s', value => expect(parseCidr(value)).toBeUndefined(),
  );
});
