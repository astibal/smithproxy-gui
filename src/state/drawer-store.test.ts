import {describe, expect, it} from 'vitest';
import {DrawerStore} from './drawer-store';

describe('DrawerStore', () => {
  it('builds a nested drawer chain', () => {
    const store = new DrawerStore();
    store.open({kind: 'policy', id: 'office', title: 'office'});
    store.open({kind: 'address', id: 'office-net', title: 'office-net'});

    expect(store.entries.map(entry => entry.kind)).toEqual(['policy', 'address']);
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
});
