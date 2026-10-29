import {describe, expect, it} from 'vitest';
import {classifyFreshness, freshnessLabel} from './freshness';

describe('monitoring freshness', () => {
  it('classifies samples against their expected collection interval', () => {
    expect(classifyFreshness(90_000, 5_000, 100_000)).toEqual({state: 'fresh', ageMs: 10_000});
    expect(classifyFreshness(80_000, 5_000, 100_000)).toEqual({state: 'aging', ageMs: 20_000});
    expect(classifyFreshness(60_000, 5_000, 100_000)).toEqual({state: 'stale', ageMs: 40_000});
  });

  it('distinguishes a missing success from an old one', () => {
    expect(classifyFreshness(null, 5_000, 100_000)).toEqual({state: 'never', ageMs: null});
    expect(classifyFreshness(Number.NaN, 5_000, 100_000)).toEqual({state: 'never', ageMs: null});
    expect(freshnessLabel('never')).toBe('No data');
  });

  it('tolerates small clock skew without reporting a negative age', () => {
    expect(classifyFreshness(101_000, 5_000, 100_000)).toEqual({state: 'fresh', ageMs: 0});
  });

  it('rejects invalid sampling intervals', () => {
    expect(() => classifyFreshness(90_000, 0, 100_000)).toThrow(RangeError);
    expect(() => classifyFreshness(90_000, Number.POSITIVE_INFINITY, 100_000)).toThrow(RangeError);
  });

  it('labels every freshness state', () => {
    expect(freshnessLabel('fresh')).toBe('Fresh');
    expect(freshnessLabel('aging')).toBe('Aging');
    expect(freshnessLabel('stale')).toBe('Stale');
    expect(freshnessLabel('never')).toBe('No data');
  });
});
