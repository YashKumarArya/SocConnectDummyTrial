export const normalizationRepo = {
  _store: new Map<string, any>(),
  async save(id?: string, normalized?: any) {
    if (!id || !normalized) return;
    this._store.set(id, { normalized, savedAt: Date.now() });
    return this._store.get(id);
  },
  async get(id: string) {
    return this._store.get(id);
  }
};
