import type {ProbeSample, SmithproxyState} from '../api/system-client';

export interface ProbeIncident {
  startedAtUnixMs: number;
  lastFailureAtUnixMs: number;
  recoveredAtUnixMs: number | null;
  samples: number;
  states: ReadonlyArray<Exclude<SmithproxyState, 'ready'>>;
}

export function probeIncidents(history: ReadonlyArray<ProbeSample>): ReadonlyArray<ProbeIncident> {
  const incidents: ProbeIncident[] = [];
  let active: ProbeIncident | undefined;

  for (const sample of history) {
    if (sample.state === 'ready') {
      if (active) {
        active.recoveredAtUnixMs = sample.checkedAtUnixMs;
        incidents.push(active);
        active = undefined;
      }
      continue;
    }

    if (!active) {
      active = {
        startedAtUnixMs: sample.checkedAtUnixMs,
        lastFailureAtUnixMs: sample.checkedAtUnixMs,
        recoveredAtUnixMs: null,
        samples: 1,
        states: [sample.state],
      };
      continue;
    }

    active.lastFailureAtUnixMs = sample.checkedAtUnixMs;
    active.samples += 1;
    if (active.states.at(-1) !== sample.state) active.states = [...active.states, sample.state];
  }

  if (active) incidents.push(active);
  return incidents;
}
