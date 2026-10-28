import {describe, expect, it} from 'vitest';
import {drawerRouteSearch, parseDrawerRoute} from './drawer-route';

describe('drawer route', () => {
  it('round-trips a nested editor chain while preserving unrelated parameters', () => {
    const search = drawerRouteSearch('?view=compact', [
      {kind: 'policy', id: 'policy-office'},
      {kind: 'address', id: 'address-office-net'},
      {kind: 'port', id: 'port-https'},
    ]);

    expect(search).toContain('view=compact');
    expect(parseDrawerRoute(search)).toEqual([
      {kind: 'policy', id: 'policy-office'},
      {kind: 'address', id: 'address-office-net'},
      {kind: 'port', id: 'port-https'},
    ]);
  });

  it('removes only the editor route', () => {
    expect(drawerRouteSearch('?edit=policy%3Aoffice&view=compact', [])).toBe('?view=compact');
  });

  it.each([
    '?edit=unknown:item',
    '?edit=policy:../secret',
    '?edit=policy:one,policy:one',
    '?edit=policy:one:two',
    '?edit=policy:1,address:2,policy:3,address:4,policy:5,address:6,policy:7',
  ])('rejects an unsafe route: %s', search => {
    expect(parseDrawerRoute(search)).toEqual([]);
  });
});
