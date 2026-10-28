import {describe, expect, it} from 'vitest';
import {statusFromFailure, statusFromHealth, statusTone} from './system-status';

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

  it('maps transport failures to an offline core without leaking an assumed upstream state', () => {
    const status = statusFromFailure(new Error('Connection failed'));
    expect(status).toMatchObject({core: 'offline', smithproxy: 'unknown', detail: 'Connection failed'});
    expect(statusTone(status)).toBe('danger');
  });
});
