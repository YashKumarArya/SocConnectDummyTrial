import { randomUUID } from 'crypto';

export type IngestRecord = {
  id: string;
  alpha_id?: string | null;
  payload: any;
  _receivedAt: number;
  _processed: boolean;
  _processedAt?: number;
  _processing?: boolean;
  _processingAt?: number;
  _processingBy?: string;
  _failed?: boolean;
  _failedAt?: number;
};

export const ingestionRepo = {
  _store: new Map<string, IngestRecord>(),

  /**
   * Save a raw alert. Will derive id from alpha_id/alphaId/id or generate one.
   * If a record already exists it will merge by default (won't overwrite _processed records unless allowOverwrite=true).
   */
  async saveRaw(alert?: any, opts?: { allowOverwrite?: boolean }) {
    if (!alert) return;

    const id =
      alert?.alpha_id || alert?.alphaId || alert?.id || (typeof randomUUID === 'function' ? randomUUID() : String(Date.now()));

    const existing = this._store.get(id) as IngestRecord | undefined;

    if (existing && existing._processed && !opts?.allowOverwrite) {
      // do not overwrite already processed alerts by default
      return existing;
    }

    const rec: IngestRecord = {
      id,
      alpha_id: alert?.alpha_id || alert?.alphaId || null,
      payload: alert,
      _receivedAt: Date.now(),
      _processed: existing ? existing._processed : false,
      _processedAt: existing?._processedAt,
      _processing: false,
      _failed: false
    };

    // merge metadata from existing where appropriate
    if (existing) {
      rec._processing = existing._processing ?? false;
      rec._processingAt = existing._processingAt;
      rec._processingBy = existing._processingBy;
      rec._failed = existing._failed ?? false;
      rec._failedAt = existing._failedAt;
    }

    this._store.set(id, rec);
    return rec;
  },

  async get(id: string) {
    return this._store.get(id);
  },

  async getByAlphaId(alphaId: string) {
    for (const v of this._store.values()) {
      if (v.alpha_id === alphaId) return v;
    }
    return undefined;
  },

  /**
   * List unprocessed items and acquire a processing lease so workers don't process same item concurrently.
   * - limit: max items to return
   * - leaseMs: how long the lease lasts before another worker can reclaim (default 60s)
   */
  async listUnprocessed(limit = 50, leaseMs = 60_000) {
    const now = Date.now();
    const items: IngestRecord[] = [];

    for (const [k, v] of this._store.entries()) {
      if (items.length >= limit) break;

      // Skip if already processed
      if (v._processed) continue;

      // If not being processed, acquire it
      if (!v._processing) {
        v._processing = true;
        v._processingAt = now;
        v._processingBy = `worker-${Math.random().toString(36).slice(2, 8)}`;
        this._store.set(k, v);
        items.push(v);
        continue;
      }

      // If processing lease expired, reclaim
      if (v._processingAt && v._processingAt + leaseMs < now) {
        v._processing = true;
        v._processingAt = now;
        v._processingBy = `worker-${Math.random().toString(36).slice(2, 8)}`;
        this._store.set(k, v);
        items.push(v);
        continue;
      }
    }

    return items;
  },

  /**
   * Mark an item as processed and clear processing flags
   */
  async markProcessed(id: string) {
    const rec = this._store.get(id);
    if (rec) {
      rec._processed = true;
      rec._processedAt = Date.now();
      rec._processing = false;
      rec._processingAt = undefined;
      rec._processingBy = undefined;
      this._store.set(id, rec);
    }
  },

  /**
   * Mark an item as failed and clear processing flag so it can be retried later
   */
  async markFailed(id: string) {
    const rec = this._store.get(id);
    if (rec) {
      rec._failed = true;
      rec._failedAt = Date.now();
      rec._processing = false;
      rec._processingAt = undefined;
      rec._processingBy = undefined;
      this._store.set(id, rec);
    }
  },

  /**
   * Release processing lease without marking processed (e.g., when worker dies or wants to put back)
   */
  async releaseProcessing(id: string) {
    const rec = this._store.get(id);
    if (rec) {
      rec._processing = false;
      rec._processingAt = undefined;
      rec._processingBy = undefined;
      this._store.set(id, rec);
    }
  },

  /**
   * For debugging / small admin tasks
   */
  async stats() {
    let total = 0;
    let processed = 0;
    let processing = 0;
    let failed = 0;
    for (const v of this._store.values()) {
      total++;
      if (v._processed) processed++;
      if (v._processing) processing++;
      if (v._failed) failed++;
    }
    return { total, processed, processing, failed };
  }
};
