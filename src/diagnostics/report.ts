export type RuntimeDiagnosticState = 'starting' | 'ready' | 'unavailable' | 'unconfigured';
export type InterfaceDiagnosticState = RuntimeDiagnosticState | 'degraded' | 'not-advertised';
export type GatewayDiagnosticState = 'verified' | 'rejected' | 'disabled' | 'unavailable' | 'discovering';
export type EventStreamDiagnosticState = 'connecting' | 'live' | 'paused' | 'invalid' | 'unavailable';
export type CapabilityBootstrapDiagnosticState = 'discovering' | 'refreshing' | 'ready' | 'unavailable';

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
    bootstrapState: CapabilityBootstrapDiagnosticState;
    checkedAtUnixMs: number | null;
    lastSuccessAtUnixMs: number | null;
    enabledFeatureCount: number;
    configRead: boolean;
    configWrite: boolean;
    drafts: boolean;
    draftPreflight: boolean;
    jobs: boolean;
    eventsAvailable: boolean;
    alertsAvailable: boolean;
    auditAvailable: boolean;
    metrics: boolean;
    sessionActivity: boolean;
    tlsMonitoring: boolean;
    neighborMonitoring: boolean;
    interfaceMonitoring: boolean;
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
  interfaces: Omit<TimedAggregateInput, 'state'> & {
    state: InterfaceDiagnosticState;
    generation: number;
    synchronizationRunning: boolean;
    synchronizationAttempts: number;
    synchronizationSuccesses: number;
    synchronizationErrors: number;
    eventDatagrams: number;
    changedEventDatagrams: number;
    interfaces: number;
    addresses: number;
    ipv4Addresses: number;
    ipv6Addresses: number;
    lastErrorCode: string | null;
  };
  operations: {
    eventStream: EventStreamDiagnosticState;
    eventStreamConnectedAtUnixMs: number | null;
    eventStreamLastMessageAtUnixMs: number | null;
    eventStreamLastDisconnectAtUnixMs: number | null;
    eventStreamReconnectCount: number;
    eventCount: number;
    activeAlertCount: number;
    auditEntryCount: number;
    jobCount: number;
    activeJobCount: number;
    failedJobCount: number;
  };
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
      bootstrapState: input.capabilities.bootstrapState,
      checkedAtUnixMs: input.capabilities.checkedAtUnixMs === null
        ? null : safeInteger(input.capabilities.checkedAtUnixMs),
      lastSuccessAtUnixMs: input.capabilities.lastSuccessAtUnixMs === null
        ? null : safeInteger(input.capabilities.lastSuccessAtUnixMs),
      enabledFeatureCount: Math.min(13, requiredInteger(input.capabilities.enabledFeatureCount)),
      configRead: input.capabilities.configRead,
      configWrite: input.capabilities.configWrite,
      drafts: input.capabilities.drafts,
      draftPreflight: input.capabilities.draftPreflight,
      jobs: input.capabilities.jobs,
      eventsAvailable: input.capabilities.eventsAvailable,
      alertsAvailable: input.capabilities.alertsAvailable,
      auditAvailable: input.capabilities.auditAvailable,
      metrics: input.capabilities.metrics,
      sessionActivity: input.capabilities.sessionActivity,
      tlsMonitoring: input.capabilities.tlsMonitoring,
      neighborMonitoring: input.capabilities.neighborMonitoring,
      interfaceMonitoring: input.capabilities.interfaceMonitoring,
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
    interfaces: {
      state: input.interfaces.state,
      checkedAtUnixMs: input.interfaces.checkedAtUnixMs === null
        ? null : safeInteger(input.interfaces.checkedAtUnixMs),
      lastSuccessAtUnixMs: input.interfaces.lastSuccessAtUnixMs === null
        ? null : safeInteger(input.interfaces.lastSuccessAtUnixMs),
      generation: requiredInteger(input.interfaces.generation),
      synchronizationRunning: input.interfaces.synchronizationRunning,
      synchronizationAttempts: requiredInteger(input.interfaces.synchronizationAttempts),
      synchronizationSuccesses: requiredInteger(input.interfaces.synchronizationSuccesses),
      synchronizationErrors: requiredInteger(input.interfaces.synchronizationErrors),
      eventDatagrams: requiredInteger(input.interfaces.eventDatagrams),
      changedEventDatagrams: requiredInteger(input.interfaces.changedEventDatagrams),
      interfaces: requiredInteger(input.interfaces.interfaces),
      addresses: requiredInteger(input.interfaces.addresses),
      ipv4Addresses: requiredInteger(input.interfaces.ipv4Addresses),
      ipv6Addresses: requiredInteger(input.interfaces.ipv6Addresses),
      lastErrorCode: input.interfaces.lastErrorCode !== null &&
        /^[a-z][a-z0-9._-]{0,63}$/u.test(input.interfaces.lastErrorCode)
        ? input.interfaces.lastErrorCode : null,
    },
    operations: {
      eventStream: input.operations.eventStream,
      eventStreamConnectedAtUnixMs: input.operations.eventStreamConnectedAtUnixMs === null
        ? null : safeInteger(input.operations.eventStreamConnectedAtUnixMs),
      eventStreamLastMessageAtUnixMs: input.operations.eventStreamLastMessageAtUnixMs === null
        ? null : safeInteger(input.operations.eventStreamLastMessageAtUnixMs),
      eventStreamLastDisconnectAtUnixMs: input.operations.eventStreamLastDisconnectAtUnixMs === null
        ? null : safeInteger(input.operations.eventStreamLastDisconnectAtUnixMs),
      eventStreamReconnectCount: requiredInteger(input.operations.eventStreamReconnectCount),
      eventCount: requiredInteger(input.operations.eventCount),
      activeAlertCount: requiredInteger(input.operations.activeAlertCount),
      auditEntryCount: requiredInteger(input.operations.auditEntryCount),
      jobCount: requiredInteger(input.operations.jobCount),
      activeJobCount: requiredInteger(input.operations.activeJobCount),
      failedJobCount: requiredInteger(input.operations.failedJobCount),
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
