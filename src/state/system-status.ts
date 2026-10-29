import type {ProbeSample, SmithproxyState, SystemHealth, SystemSnapshot} from '../api/system-client';

export interface SystemStatus {
  core: 'connecting' | 'online' | 'offline';
  smithproxy: SmithproxyState | 'unknown';
  detail: string;
  checkedAtUnixMs: number | null;
  lastSuccessAtUnixMs: number | null;
  latencyMs: number | null;
  uptimeMs: number | null;
  totalProbes: number;
  consecutiveFailures: number;
  availabilitySamples: number;
  availabilitySuccessful: number;
  history: ReadonlyArray<ProbeSample>;
}

export const connectingSystemStatus: SystemStatus = {
  core: 'connecting',
  smithproxy: 'unknown',
  detail: 'Connecting to the Smithproxy GUI core.',
  checkedAtUnixMs: null,
  lastSuccessAtUnixMs: null,
  latencyMs: null,
  uptimeMs: null,
  totalProbes: 0,
  consecutiveFailures: 0,
  availabilitySamples: 0,
  availabilitySuccessful: 0,
  history: [],
};

export function statusFromHealth(health: SystemHealth): SystemStatus {
  return {
    core: 'online',
    smithproxy: health.smithproxy.state,
    detail: health.smithproxy.detail,
    checkedAtUnixMs: health.smithproxy.checkedAtUnixMs,
    lastSuccessAtUnixMs: health.smithproxy.state === 'ready' ? health.smithproxy.checkedAtUnixMs : null,
    latencyMs: null,
    uptimeMs: null,
    totalProbes: 0,
    consecutiveFailures: 0,
    availabilitySamples: 0,
    availabilitySuccessful: 0,
    history: [],
  };
}

export function statusFromSnapshot(snapshot: SystemSnapshot): SystemStatus {
  return {
    core: 'online',
    smithproxy: snapshot.smithproxy.state,
    detail: snapshot.smithproxy.detail,
    checkedAtUnixMs: snapshot.smithproxy.checkedAtUnixMs,
    lastSuccessAtUnixMs: snapshot.smithproxy.lastSuccessAtUnixMs,
    latencyMs: snapshot.smithproxy.latencyMs,
    uptimeMs: snapshot.uptimeMs,
    totalProbes: snapshot.smithproxy.totalProbes,
    consecutiveFailures: snapshot.smithproxy.consecutiveFailures,
    availabilitySamples: snapshot.smithproxy.availabilityWindow.samples,
    availabilitySuccessful: snapshot.smithproxy.availabilityWindow.successful,
    history: snapshot.smithproxy.history,
  };
}

export function statusFromFailure(error: unknown): SystemStatus {
  const supplied = error instanceof Error ? error.message : '';
  const detail = supplied.length > 0 && supplied.length <= 256 &&
    !/[\u0000-\u001f\u007f]/u.test(supplied)
    ? supplied
    : 'The Smithproxy GUI core is unavailable.';
  return {
    core: 'offline',
    smithproxy: 'unknown',
    detail,
    checkedAtUnixMs: null,
    lastSuccessAtUnixMs: null,
    latencyMs: null,
    uptimeMs: null,
    totalProbes: 0,
    consecutiveFailures: 0,
    availabilitySamples: 0,
    availabilitySuccessful: 0,
    history: [],
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
