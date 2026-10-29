import {describe, expect, it} from 'vitest';
import {probeIncidents} from './incidents';

describe('probeIncidents', () => {
  it('groups consecutive failures and records recovery boundaries', () => {
    expect(probeIncidents([
      {state: 'ready', checkedAtUnixMs: 10, latencyMs: 1},
      {state: 'unreachable', checkedAtUnixMs: 20, latencyMs: null},
      {state: 'error', checkedAtUnixMs: 30, latencyMs: null},
      {state: 'unreachable', checkedAtUnixMs: 35, latencyMs: null},
      {state: 'ready', checkedAtUnixMs: 40, latencyMs: 2},
      {state: 'unauthorized', checkedAtUnixMs: 50, latencyMs: null},
    ])).toEqual([
      {
        startedAtUnixMs: 20, lastFailureAtUnixMs: 35, recoveredAtUnixMs: 40,
        samples: 3, states: ['unreachable', 'error', 'unreachable'],
      },
      {
        startedAtUnixMs: 50, lastFailureAtUnixMs: 50, recoveredAtUnixMs: null,
        samples: 1, states: ['unauthorized'],
      },
    ]);
  });

  it('returns no incidents for an empty or fully ready window', () => {
    expect(probeIncidents([])).toEqual([]);
    expect(probeIncidents([
      {state: 'ready', checkedAtUnixMs: 10, latencyMs: 1},
      {state: 'ready', checkedAtUnixMs: 20, latencyMs: 2},
    ])).toEqual([]);
  });
});
