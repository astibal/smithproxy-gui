export type FreshnessState = 'fresh' | 'aging' | 'stale' | 'never';

export interface Freshness {
  state: FreshnessState;
  ageMs: number | null;
}

export function classifyFreshness(
  lastSuccessAtUnixMs: number | null,
  expectedIntervalMs: number,
  nowUnixMs = Date.now(),
): Freshness {
  if (lastSuccessAtUnixMs === null || !Number.isFinite(lastSuccessAtUnixMs)) {
    return {state: 'never', ageMs: null};
  }
  if (!Number.isFinite(expectedIntervalMs) || expectedIntervalMs <= 0) {
    throw new RangeError('The expected sampling interval must be positive.');
  }

  const ageMs = Math.max(0, nowUnixMs - lastSuccessAtUnixMs);
  if (ageMs <= expectedIntervalMs * 2.5) return {state: 'fresh', ageMs};
  if (ageMs <= expectedIntervalMs * 6) return {state: 'aging', ageMs};
  return {state: 'stale', ageMs};
}

export function freshnessLabel(state: FreshnessState): string {
  switch (state) {
    case 'fresh': return 'Fresh';
    case 'aging': return 'Aging';
    case 'stale': return 'Stale';
    case 'never': return 'No data';
  }
}
