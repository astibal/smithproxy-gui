export type DrawerKind =
  'policy' | 'policy-create' | 'address' | 'address-create' | 'port' | 'port-create' | 'protocol' | 'protocol-create' |
  'profile' | 'profile-create' | 'auth-identities' | 'auth-identities-create' |
  'settings' | 'captures' | 'authority' | 'authority-create' |
  'signature' | 'signature-create' | 'signature-flow' | 'signature-flow-create' |
  'content-rule' | 'content-rule-create';

export interface DrawerEntry {
  kind: DrawerKind;
  id: string;
  title: string;
}

export const MAXIMUM_DRAWER_DEPTH = 6;

export class DrawerStore {
  #entries: DrawerEntry[] = [];

  get entries(): ReadonlyArray<DrawerEntry> {
    return this.#entries;
  }

  open(entry: DrawerEntry): boolean {
    const existing = this.#entries.findIndex(item => item.kind === entry.kind && item.id === entry.id);
    if (existing >= 0) {
      this.#entries = this.#entries.slice(0, existing + 1);
      return true;
    }
    if (this.#entries.length >= MAXIMUM_DRAWER_DEPTH) return false;
    this.#entries = [...this.#entries, entry];
    return true;
  }

  closeFrom(index: number): void {
    if (index < 0 || index >= this.#entries.length) {
      return;
    }
    this.#entries = this.#entries.slice(0, index);
  }

  closeTop(): void {
    if (this.#entries.length > 0) {
      this.#entries = this.#entries.slice(0, -1);
    }
  }

  clear(): void {
    this.#entries = [];
  }
}
