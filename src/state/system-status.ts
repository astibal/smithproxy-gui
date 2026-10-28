import type {SmithproxyState, SystemHealth} from '../api/system-client';

export interface SystemStatus {
  core: 'connecting' | 'online' | 'offline';
  smithproxy: SmithproxyState | 'unknown';
  detail: string;
  checkedAtUnixMs: number | null;
}

export const connectingSystemStatus: SystemStatus = {
  core: 'connecting',
  smithproxy: 'unknown',
  detail: 'Connecting to the Smithproxy GUI core.',
  checkedAtUnixMs: null,
};

export function statusFromHealth(health: SystemHealth): SystemStatus {
  return {
    core: 'online',
    smithproxy: health.smithproxy.state,
    detail: health.smithproxy.detail,
    checkedAtUnixMs: health.smithproxy.checkedAtUnixMs,
  };
}

export function statusFromFailure(error: unknown): SystemStatus {
  return {
    core: 'offline',
    smithproxy: 'unknown',
    detail: error instanceof Error ? error.message : 'The Smithproxy GUI core is unavailable.',
    checkedAtUnixMs: null,
  };
}

export function statusTone(status: SystemStatus): 'success' | 'warning' | 'danger' | 'muted' {
  if (status.core === 'offline' || status.smithproxy === 'unauthorized' || status.smithproxy === 'error') {
    return 'danger';
  }
  if (status.core === 'connecting' || status.smithproxy === 'starting' ||
      status.smithproxy === 'unreachable' || status.smithproxy === 'unconfigured') {
    return 'warning';
  }
  if (status.smithproxy === 'ready') return 'success';
  return 'muted';
}

export function displayState(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
