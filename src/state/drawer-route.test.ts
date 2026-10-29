import {describe, expect, it} from 'vitest';
import {drawerRouteSearch, parseDrawerRoute} from './drawer-route';

describe('drawer route', () => {
  it('round-trips a nested editor chain while preserving unrelated parameters', () => {
    const search = drawerRouteSearch('?view=compact', [
      {kind: 'policy', id: 'policy-office'},
      {kind: 'address', id: 'address-office-net'},
      {kind: 'port', id: 'port-https'},
      {kind: 'profile', id: 'tls-inspect'},
    ]);

    expect(search).toContain('view=compact');
    expect(parseDrawerRoute(search)).toEqual([
      {kind: 'policy', id: 'policy-office'},
      {kind: 'address', id: 'address-office-net'},
      {kind: 'port', id: 'port-https'},
      {kind: 'profile', id: 'tls-inspect'},
    ]);
  });

  it('removes only the editor route', () => {
    expect(drawerRouteSearch('?edit=policy%3Aoffice&view=compact', [])).toBe('?view=compact');
  });

  it('accepts system configuration editors', () => {
    expect(parseDrawerRoute('?edit=address-create:create-address-1')).toEqual([
      {kind: 'address-create', id: 'create-address-1'},
    ]);
    expect(parseDrawerRoute('?edit=policy-create:create-policy-1')).toEqual([
      {kind: 'policy-create', id: 'create-policy-1'},
    ]);
    expect(parseDrawerRoute('?edit=content-rule-create:create-content-rule-1')).toEqual([
      {kind: 'content-rule-create', id: 'create-content-rule-1'},
    ]);
    expect(parseDrawerRoute('?edit=signature-flow-create:create-signature-flow-1')).toEqual([
      {kind: 'signature-flow-create', id: 'create-signature-flow-1'},
    ]);
    expect(parseDrawerRoute('?edit=port-create:create-port-1,protocol-create:create-protocol-1')).toEqual([
      {kind: 'port-create', id: 'create-port-1'},
      {kind: 'protocol-create', id: 'create-protocol-1'},
    ]);
    expect(parseDrawerRoute('?edit=settings:settings')).toEqual([{kind: 'settings', id: 'settings'}]);
    expect(parseDrawerRoute('?edit=captures:captures')).toEqual([{kind: 'captures', id: 'captures'}]);
    expect(parseDrawerRoute('?edit=authority:certificate-authority-0')).toEqual([
      {kind: 'authority', id: 'certificate-authority-0'},
    ]);
    expect(parseDrawerRoute(
      '?edit=signature:detection-signature-0,signature-flow:detection-signature-0-flow-0',
    )).toEqual([
      {kind: 'signature', id: 'detection-signature-0'},
      {kind: 'signature-flow', id: 'detection-signature-0-flow-0'},
    ]);
    expect(parseDrawerRoute('?edit=profile:content-0,content-rule:content-rule-0-0')).toEqual([
      {kind: 'profile', id: 'content-0'},
      {kind: 'content-rule', id: 'content-rule-0-0'},
    ]);
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
