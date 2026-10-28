export type DrawerKind = 'policy' | 'address' | 'port' | 'protocol' | 'profile' | 'settings' | 'captures';

export interface DrawerEntry {
  kind: DrawerKind;
  id: string;
  title: string;
}
export class DrawerStore {
  #entries: DrawerEntry[] = [];

  get entries(): ReadonlyArray<DrawerEntry> {
    return this.#entries;
  }

  open(entry: DrawerEntry): void {
    const existing = this.#entries.findIndex(item => item.kind === entry.kind && item.id === entry.id);
    if (existing >= 0) {
      this.#entries = this.#entries.slice(0, existing + 1);
      return;
    }
    this.#entries = [...this.#entries, entry];
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
