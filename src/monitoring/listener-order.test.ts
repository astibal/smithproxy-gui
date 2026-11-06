import {describe, expect, it} from 'vitest';
import {orderListenerWorkloads, type ListenerWorkload} from './listener-order';

const listener = (
  name: string, workers: number, sessionsActive: number, sessionsTotal = sessionsActive,
): ListenerWorkload => ({name, workers, sessionsActive, sessionsTotal});

describe('listener workload ordering', () => {
  it('prioritizes real activity over protocol preference and configured capacity', () => {
    expect(orderListenerWorkloads([
      listener('tls', 8, 1), listener('tcp', 2, 5), listener('quic', 16, 0),
    ]).map(item => item.name)).toEqual(['tcp', 'tls', 'quic']);
  });

  it('moves unused listeners to the bottom and uses stable protocol preferences for ties', () => {
    expect(orderListenerWorkloads([
      listener('udp', 0, 0), listener('tcp', 0, 0), listener('tls', 0, 0),
    ]).map(item => item.name)).toEqual(['tls', 'tcp', 'udp']);
  });
});
