import {describe, expect, it} from 'vitest';
import {DrawerStore, MAXIMUM_DRAWER_DEPTH} from './drawer-store';

describe('DrawerStore', () => {
  it('builds a nested drawer chain', () => {
    const store = new DrawerStore();
    store.open({kind: 'policy', id: 'office', title: 'office'});
    store.open({kind: 'address', id: 'office-net', title: 'office-net'});
    store.open({kind: 'port', id: 'https', title: 'https'});

    expect(store.entries.map(entry => entry.kind)).toEqual(['policy', 'address', 'port']);
  });

  it('returns to an already open entry without duplicating it', () => {
    const store = new DrawerStore();
    const policy = {kind: 'policy' as const, id: 'office', title: 'office'};
    store.open(policy);
    store.open({kind: 'address', id: 'office-net', title: 'office-net'});
    store.open(policy);

    expect(store.entries).toEqual([policy]);
  });

  it('closes an entry and all descendants', () => {
    const store = new DrawerStore();
    store.open({kind: 'policy', id: 'office', title: 'office'});
    store.open({kind: 'address', id: 'office-net', title: 'office-net'});
    store.closeFrom(0);

    expect(store.entries).toEqual([]);
  });

  it('bounds the live chain at the same depth as persisted routes', () => {
    const store = new DrawerStore();
    for (let index = 0; index < MAXIMUM_DRAWER_DEPTH; index += 1) {
      expect(store.open({kind: 'address', id: `address-${index}`, title: `Address ${index}`})).toBe(true);
    }

    expect(store.open({kind: 'address', id: 'address-overflow', title: 'Overflow'})).toBe(false);
    expect(store.entries).toHaveLength(MAXIMUM_DRAWER_DEPTH);
    expect(store.open({kind: 'address', id: 'address-2', title: 'Address 2'})).toBe(true);
    expect(store.entries).toHaveLength(3);
  });

  it('closes only the top entry and can clear the chain', () => {
    const store = new DrawerStore();
    store.closeTop();
    store.open({kind: 'policy', id: 'office', title: 'office'});
    store.open({kind: 'address', id: 'office-net', title: 'office-net'});

    store.closeTop();
    expect(store.entries.map(entry => entry.id)).toEqual(['office']);
    store.clear();
    expect(store.entries).toEqual([]);
  });

  it('ignores invalid close indexes without changing the chain', () => {
    const store = new DrawerStore();
    store.open({kind: 'policy', id: 'office', title: 'office'});

    store.closeFrom(-1);
    store.closeFrom(1);
    expect(store.entries.map(entry => entry.id)).toEqual(['office']);
  });
});
