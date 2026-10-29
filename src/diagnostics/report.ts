export type RuntimeDiagnosticState = 'starting' | 'ready' | 'unavailable' | 'unconfigured';
export type GatewayDiagnosticState = 'verified' | 'rejected' | 'disabled' | 'unavailable' | 'discovering';
export type EventStreamDiagnosticState = 'connecting' | 'live' | 'paused' | 'invalid';

interface TimedAggregateInput {
  state: RuntimeDiagnosticState;
  checkedAtUnixMs: number | null;
  lastSuccessAtUnixMs: number | null;
}

export interface DiagnosticsReportInput {
  generatedAtUnixMs: number;
  application: {mode: 'standalone' | 'embedded'; apiVersion: string};
  controlPlane: {
    core: 'connecting' | 'online' | 'offline';
    smithproxy: 'starting' | 'ready' | 'unreachable' | 'unauthorized' | 'unconfigured' | 'error' | 'unknown';
    checkedAtUnixMs: number | null;
    lastSuccessAtUnixMs: number | null;
    latencyMs: number | null;
    totalProbes: number;
    consecutiveFailures: number;
    availabilitySamples: number;
    availabilitySuccessful: number;
  };
  gateway: {mode: 'gateway' | 'disabled' | 'unknown'; authenticated: boolean | null; state: GatewayDiagnosticState};
  capabilities: {
    configRead: boolean;
    configWrite: boolean;
    drafts: boolean;
    draftPreflight: boolean;
    configTransaction: 'starting' | 'not-advertised' | 'review-required' | 'incompatible' | 'unavailable' | 'ready' | 'unknown';
  };
  runtime: TimedAggregateInput & {
    workers: number; sessionsTotal: number; sessionsActive: number; bytesUp: number; bytesDown: number; listenerCount: number;
  };
  sessionActivity: TimedAggregateInput & {total: number; speedUp: number; speedDown: number; protocolCount: number};
  tlsCache: TimedAggregateInput & {size: number; capacity: number};
  neighbors: TimedAggregateInput & {
    hostsTotal: number; activeToday: number; activeWeek: number; taggedHosts: number;
    observations: number; bytesUp: number; bytesDown: number;
  };
  operations: {eventStream: EventStreamDiagnosticState; eventCount: number; activeAlertCount: number; auditEntryCount: number};
  configuration: {source: 'live' | 'preview' | 'unavailable'; state: RuntimeDiagnosticState | 'unknown'; draftChangeCount: number};
}

export interface DiagnosticsReport extends DiagnosticsReportInput {
  schemaVersion: 1;
}

function safeInteger(value: number): number | null {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function requiredInteger(value: number): number {
  return safeInteger(value) ?? 0;
}

function timedAggregate(value: TimedAggregateInput): TimedAggregateInput {
  return {
    state: value.state,
    checkedAtUnixMs: value.checkedAtUnixMs === null ? null : safeInteger(value.checkedAtUnixMs),
    lastSuccessAtUnixMs: value.lastSuccessAtUnixMs === null ? null : safeInteger(value.lastSuccessAtUnixMs),
  };
}

export function buildDiagnosticsReport(input: DiagnosticsReportInput): DiagnosticsReport {
  return {
    schemaVersion: 1,
    generatedAtUnixMs: requiredInteger(input.generatedAtUnixMs),
    application: {
      mode: input.application.mode,
      apiVersion: /^v[0-9]{1,4}$/.test(input.application.apiVersion) ? input.application.apiVersion : 'unknown',
    },
    controlPlane: {
      core: input.controlPlane.core,
      smithproxy: input.controlPlane.smithproxy,
      checkedAtUnixMs: input.controlPlane.checkedAtUnixMs === null ? null : safeInteger(input.controlPlane.checkedAtUnixMs),
      lastSuccessAtUnixMs: input.controlPlane.lastSuccessAtUnixMs === null ? null : safeInteger(input.controlPlane.lastSuccessAtUnixMs),
      latencyMs: input.controlPlane.latencyMs === null ? null : safeInteger(input.controlPlane.latencyMs),
      totalProbes: requiredInteger(input.controlPlane.totalProbes),
      consecutiveFailures: requiredInteger(input.controlPlane.consecutiveFailures),
      availabilitySamples: requiredInteger(input.controlPlane.availabilitySamples),
      availabilitySuccessful: requiredInteger(input.controlPlane.availabilitySuccessful),
    },
    gateway: {
      mode: input.gateway.mode,
      authenticated: input.gateway.authenticated,
      state: input.gateway.state,
    },
    capabilities: {
      configRead: input.capabilities.configRead,
      configWrite: input.capabilities.configWrite,
      drafts: input.capabilities.drafts,
      draftPreflight: input.capabilities.draftPreflight,
      configTransaction: input.capabilities.configTransaction,
    },
    runtime: {
      ...timedAggregate(input.runtime),
      workers: requiredInteger(input.runtime.workers),
      sessionsTotal: requiredInteger(input.runtime.sessionsTotal),
      sessionsActive: requiredInteger(input.runtime.sessionsActive),
      bytesUp: requiredInteger(input.runtime.bytesUp),
      bytesDown: requiredInteger(input.runtime.bytesDown),
      listenerCount: requiredInteger(input.runtime.listenerCount),
    },
    sessionActivity: {
      ...timedAggregate(input.sessionActivity),
      total: requiredInteger(input.sessionActivity.total),
      speedUp: requiredInteger(input.sessionActivity.speedUp),
      speedDown: requiredInteger(input.sessionActivity.speedDown),
      protocolCount: requiredInteger(input.sessionActivity.protocolCount),
    },
    tlsCache: {
      ...timedAggregate(input.tlsCache),
      size: requiredInteger(input.tlsCache.size),
      capacity: requiredInteger(input.tlsCache.capacity),
    },
    neighbors: {
      ...timedAggregate(input.neighbors),
      hostsTotal: requiredInteger(input.neighbors.hostsTotal),
      activeToday: requiredInteger(input.neighbors.activeToday),
      activeWeek: requiredInteger(input.neighbors.activeWeek),
      taggedHosts: requiredInteger(input.neighbors.taggedHosts),
      observations: requiredInteger(input.neighbors.observations),
      bytesUp: requiredInteger(input.neighbors.bytesUp),
      bytesDown: requiredInteger(input.neighbors.bytesDown),
    },
    operations: {
      eventStream: input.operations.eventStream,
      eventCount: requiredInteger(input.operations.eventCount),
      activeAlertCount: requiredInteger(input.operations.activeAlertCount),
      auditEntryCount: requiredInteger(input.operations.auditEntryCount),
    },
    configuration: {
      source: input.configuration.source,
      state: input.configuration.state,
      draftChangeCount: requiredInteger(input.configuration.draftChangeCount),
    },
  };
}

export function serializeDiagnosticsReport(report: DiagnosticsReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}
