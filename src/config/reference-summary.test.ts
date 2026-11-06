import {describe, expect, it} from 'vitest';
import {referenceNameSummary} from './reference-summary';

describe('configuration reference summaries', () => {
  it('shows short lists in full', () => {
    expect(referenceNameSummary([])).toBe('None');
    expect(referenceNameSummary(['any'])).toBe('any');
    expect(referenceNameSummary(['any', 'any6'])).toBe('any, any6');
    expect(referenceNameSummary(['office', 'vpn', 'local'])).toBe('office, vpn, local');
  });

  it('bounds longer lists without hiding the second reference', () => {
    expect(referenceNameSummary(['office', 'vpn', 'local', 'partners']))
      .toBe('office, vpn +2');
  });
});
