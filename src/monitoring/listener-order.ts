export interface ListenerWorkload {
  name: string;
  workers: number;
  sessionsTotal: number;
  sessionsActive: number;
}

const preferredListenerOrder = new Map([
  ['tls', 0], ['tcp', 1], ['plaintext', 1], ['quic', 2], ['dtls', 3], ['udp', 4],
  ['http-connect', 5], ['socks', 6],
]);

/**
 * Keeps live workloads above configured-but-idle and unused listeners. The
 * protocol preference only resolves otherwise equal rows, so actual activity
 * remains the primary signal.
 */
export function orderListenerWorkloads<T extends ListenerWorkload>(listeners: ReadonlyArray<T>): T[] {
  const activityBand = (listener: T): number => listener.sessionsActive > 0 ? 2 : listener.workers > 0 ? 1 : 0;
  const protocolRank = (listener: T): number => preferredListenerOrder.get(listener.name.toLowerCase()) ?? 100;
  return [...listeners].sort((left, right) =>
    activityBand(right) - activityBand(left) ||
    right.sessionsActive - left.sessionsActive ||
    right.workers - left.workers ||
    right.sessionsTotal - left.sessionsTotal ||
    protocolRank(left) - protocolRank(right) ||
    left.name.localeCompare(right.name));
}
