import {describe, expect, it} from 'vitest';
import {isConfigGroupName} from './config-name';

describe('libconfig group names', () => {
  it.each(['office', '_internal', 'tls-profile-1', 'A'])('accepts %s', value => {
    expect(isConfigGroupName(value)).toBe(true);
  });

  it.each(['', '1office', 'office network', 'office.example', 'é', `${'a'.repeat(129)}`])(
    'rejects %s', value => expect(isConfigGroupName(value)).toBe(false),
  );
});
