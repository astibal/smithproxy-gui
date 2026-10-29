import type {DrawerEntry, DrawerKind} from './drawer-store';

export interface DrawerRouteEntry {
  kind: DrawerKind;
  id: string;
}

const maximumDepth = 6;
const safeIdentifier = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/u;
const drawerKinds = new Set<DrawerKind>([
  'policy', 'address', 'port', 'protocol', 'profile', 'settings', 'captures', 'authority',
  'signature', 'signature-flow',
  'content-rule',
]);

export function parseDrawerRoute(search: string): ReadonlyArray<DrawerRouteEntry> {
  const encoded = new URLSearchParams(search).get('edit');
  if (!encoded) return [];
  const result: DrawerRouteEntry[] = [];
  const identities = new Set<string>();
  for (const segment of encoded.split(',')) {
    const separator = segment.indexOf(':');
    if (separator <= 0 || separator !== segment.lastIndexOf(':')) return [];
    const kind = segment.slice(0, separator);
    const id = segment.slice(separator + 1);
    if (!drawerKinds.has(kind as DrawerKind) || !safeIdentifier.test(id)) return [];
    const identity = `${kind}:${id}`;
    if (identities.has(identity) || result.length >= maximumDepth) return [];
    identities.add(identity);
    result.push({kind: kind as DrawerKind, id});
  }
  return result;
}

export function drawerRouteSearch(
  search: string,
  entries: ReadonlyArray<Pick<DrawerEntry, 'kind' | 'id'>>,
): string {
  const parameters = new URLSearchParams(search);
  if (entries.length === 0) {
    parameters.delete('edit');
  } else {
    parameters.set('edit', entries.map(entry => `${entry.kind}:${entry.id}`).join(','));
  }
  const serialized = parameters.toString();
  return serialized.length > 0 ? `?${serialized}` : '';
}
