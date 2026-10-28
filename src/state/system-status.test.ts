import {describe, expect, it} from 'vitest';
import {statusFromFailure, statusFromHealth, statusFromSnapshot, statusTone} from './system-status';

describe('system status mapping', () => {
  it('maps a ready health response to a successful online state', () => {
    const status = statusFromHealth({
      status: 'ok', smithproxy: {state: 'ready', detail: 'Connected', checkedAtUnixMs: 42},
    });
    expect(status).toMatchObject({core: 'online', smithproxy: 'ready', checkedAtUnixMs: 42});
    expect(statusTone(status)).toBe('success');
  });

  it('keeps core connectivity separate from an unreachable Smithproxy', () => {
    const status = statusFromHealth({
      status: 'ok', smithproxy: {state: 'unreachable', detail: 'Timed out', checkedAtUnixMs: 42},
    });
    expect(status).toMatchObject({core: 'online', smithproxy: 'unreachable'});
    expect(statusTone(status)).toBe('warning');
  });

  it('maps monitoring counters without conflating them with core connectivity', () => {
    const status = statusFromSnapshot({
      service: 'smithproxy-gui', uptimeMs: 5000,
      smithproxy: {
        configured: true, state: 'unreachable', detail: 'Timed out', checkedAtUnixMs: 42,
        lastSuccessAtUnixMs: 20, latencyMs: 2500, totalProbes: 4, consecutiveFailures: 2,
        availabilityWindow: {samples: 4, successful: 2},
        history: [{state: 'unreachable', checkedAtUnixMs: 42, latencyMs: 2500}],
      },
    });
    expect(status).toMatchObject({
      core: 'online', smithproxy: 'unreachable', uptimeMs: 5000,
      totalProbes: 4, consecutiveFailures: 2, availabilitySuccessful: 2,
    });
  });

  it('maps transport failures to an offline core without leaking an assumed upstream state', () => {
    const status = statusFromFailure(new Error('Connection failed'));
    expect(status).toMatchObject({core: 'offline', smithproxy: 'unknown', detail: 'Connection failed'});
    expect(statusTone(status)).toBe('danger');
  });
});
