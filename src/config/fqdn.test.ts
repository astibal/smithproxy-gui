import {describe, expect, it} from 'vitest';
import {describeFqdn, parseFqdn} from './fqdn';

describe('FQDN insights', () => {
  it('normalizes host names and preserves absolute-name posture', () => {
    expect(parseFqdn('WWW.Example.COM.')).toEqual({
      normalized: 'www.example.com', labels: 3, absolute: true,
    });
    expect(describeFqdn('WWW.Example.COM.'))
      .toBe('Valid DNS absolute name · 3 labels · www.example.com');
    expect(describeFqdn('internal-host'))
      .toBe('Valid DNS host name · 1 label · internal-host');
  });

  it.each([
    '', 'bad..example', '-bad.example', 'bad-.example', 'bad_name.example',
    '192.0.2.1', '2001:db8::1', 'non-ascii-é.example', `${'a'.repeat(64)}.example`,
  ])('rejects invalid DNS host name %s', value => expect(parseFqdn(value)).toBeUndefined());
});
