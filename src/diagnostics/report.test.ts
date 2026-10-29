import {describe, expect, it} from 'vitest';
import {buildDiagnosticsReport, serializeDiagnosticsReport, type DiagnosticsReportInput} from './report';

function fixture(): DiagnosticsReportInput {
  const timed = {state: 'ready' as const, checkedAtUnixMs: 1_700_000_000_000, lastSuccessAtUnixMs: 1_699_999_999_000};
  return {
    generatedAtUnixMs: 1_700_000_000_500,
    application: {mode: 'embedded', apiVersion: 'v1'},
    controlPlane: {
      core: 'online', smithproxy: 'ready', checkedAtUnixMs: 1_700_000_000_000,
      lastSuccessAtUnixMs: 1_699_999_999_000, latencyMs: 12, totalProbes: 9,
      consecutiveFailures: 0, availabilitySamples: 8, availabilitySuccessful: 8,
    },
    gateway: {mode: 'gateway', authenticated: true, state: 'verified'},
    capabilities: {
      bootstrapState: 'ready', checkedAtUnixMs: 1_700_000_000_000,
      lastSuccessAtUnixMs: 1_699_999_999_000, enabledFeatureCount: 12,
      configRead: true, configWrite: false, drafts: true, draftPreflight: true,
      jobs: true, eventsAvailable: true, alertsAvailable: true, auditAvailable: true, metrics: true,
      sessionActivity: true, tlsMonitoring: true, neighborMonitoring: true,
      interfaceMonitoring: true,
      configTransaction: 'review-required',
    },
    runtime: {...timed, workers: 3, sessionsTotal: 19, sessionsActive: 4, bytesUp: 1536, bytesDown: 2304, listenerCount: 2},
    sessionActivity: {...timed, total: 4, speedUp: 512, speedDown: 1024, protocolCount: 2},
    tlsCache: {...timed, size: 42, capacity: 1000},
    neighbors: {...timed, hostsTotal: 8, activeToday: 3, activeWeek: 7, taggedHosts: 2, observations: 22, bytesUp: 4096, bytesDown: 8192},
    interfaces: {
      ...timed, generation: 42, synchronizationRunning: true,
      synchronizationAttempts: 3, synchronizationSuccesses: 3, synchronizationErrors: 0,
      eventDatagrams: 15, changedEventDatagrams: 4, interfaces: 3, addresses: 5,
      ipv4Addresses: 3, ipv6Addresses: 2, lastErrorCode: null,
    },
    operations: {
      eventStream: 'live', eventStreamConnectedAtUnixMs: 1_700_000_000_000,
      eventStreamLastMessageAtUnixMs: 1_700_000_000_100,
      eventStreamLastDisconnectAtUnixMs: 1_699_999_990_000, eventStreamReconnectCount: 2,
      eventCount: 4, activeAlertCount: 0, auditEntryCount: 2,
      jobCount: 3, activeJobCount: 1, failedJobCount: 1,
    },
    configuration: {source: 'live', state: 'ready', draftChangeCount: 1},
  };
}

describe('diagnostics report', () => {
  it('serializes only aggregate allowlisted fields', () => {
    const serialized = serializeDiagnosticsReport(buildDiagnosticsReport(fixture()));
    const report = JSON.parse(serialized) as Record<string, unknown>;

    expect(report).toMatchObject({
      schemaVersion: 1,
      application: {mode: 'embedded', apiVersion: 'v1'},
      runtime: {listenerCount: 2, sessionsActive: 4},
      interfaces: {generation: 42, interfaces: 3, addresses: 5},
      capabilities: {bootstrapState: 'ready', enabledFeatureCount: 12,
        jobs: true, metrics: true, interfaceMonitoring: true,
        eventsAvailable: true, alertsAvailable: true, auditAvailable: true},
      operations: {
        eventStream: 'live', eventStreamReconnectCount: 2,
        eventCount: 4, activeAlertCount: 0, auditEntryCount: 2,
        jobCount: 3, activeJobCount: 1, failedJobCount: 1,
      },
      configuration: {source: 'live', state: 'ready', draftChangeCount: 1},
    });
    expect(serialized).not.toMatch(/"(detail|basePath|revision|listeners|protocols|events|alerts|auditEntries|targets|requestId|secret|token)"/i);
  });

  it('normalizes invalid free-form and numeric values', () => {
    const input = fixture();
    input.application.apiVersion = 'v1 private-token';
    input.runtime.sessionsActive = -1;
    input.controlPlane.latencyMs = Number.NaN;
    input.generatedAtUnixMs = Number.MAX_VALUE;
    input.capabilities.checkedAtUnixMs = -1;
    input.capabilities.lastSuccessAtUnixMs = Number.NaN;
    input.capabilities.enabledFeatureCount = 99;
    input.operations.eventStreamConnectedAtUnixMs = -1;
    input.operations.eventStreamLastMessageAtUnixMs = Number.NaN;
    input.operations.eventStreamLastDisconnectAtUnixMs = Number.MAX_VALUE;
    input.operations.eventStreamReconnectCount = -1;
    input.interfaces.lastErrorCode = 'raw kernel error';

    const report = buildDiagnosticsReport(input);
    expect(report.application.apiVersion).toBe('unknown');
    expect(report.runtime.sessionsActive).toBe(0);
    expect(report.controlPlane.latencyMs).toBeNull();
    expect(report.generatedAtUnixMs).toBe(0);
    expect(report.capabilities.checkedAtUnixMs).toBeNull();
    expect(report.capabilities.lastSuccessAtUnixMs).toBeNull();
    expect(report.capabilities.enabledFeatureCount).toBe(13);
    expect(report.operations.eventStreamConnectedAtUnixMs).toBeNull();
    expect(report.operations.eventStreamLastMessageAtUnixMs).toBeNull();
    expect(report.operations.eventStreamLastDisconnectAtUnixMs).toBeNull();
    expect(report.operations.eventStreamReconnectCount).toBe(0);
    expect(report.interfaces.lastErrorCode).toBeNull();
  });
});
