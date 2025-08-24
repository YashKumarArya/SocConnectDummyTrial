// Lightweight Redis-backed dedupe helper with in-memory fallback

async function tryImportIoredis() {
  try {
    // @ts-ignore - ioredis is optional; dynamically import if present
    const mod: any = await import('ioredis');
    return mod.default || mod;
  } catch (e) {
    return null;
  }
}

let _client: any = null;
let _inMemory: Map<string, number> | null = null;

async function getClient() {
  if (_client) return _client;
  const Redis = await tryImportIoredis();
  if (Redis) {
    const url = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
    _client = new Redis(url);
    _client.on('error', (e: any) => console.warn('redis client error', e?.message || e));
    return _client;
  }
  // fallback to in-memory map with TTL semantics
  if (!_inMemory) _inMemory = new Map();
  return null;
}

export async function setIfNotExists(key: string, ttlMs = 24 * 60 * 60 * 1000): Promise<boolean> {
  const client = await getClient();
  // If redis available, use SET NX PX
  if (client) {
    try {
      const res = await client.set(key, '1', 'PX', String(ttlMs), 'NX');
      return res === 'OK';
    } catch (e: any) {
      console.warn('redis setIfNotExists failed', e?.message || e);
      // fall through to in-memory
    }
  }

  // in-memory fallback
  if (!_inMemory) _inMemory = new Map();
  const now = Date.now();
  const expiresAt = _inMemory.get(key) || 0;
  if (expiresAt > now) return false;
  _inMemory.set(key, now + ttlMs);
  // schedule cleanup
  setTimeout(() => {
    const cur = _inMemory?.get(key) || 0;
    if (cur <= Date.now()) _inMemory?.delete(key);
  }, ttlMs + 1000);
  return true;
}

export async function del(key: string) {
  const client = await getClient();
  if (client) {
    try { await client.del(key); return true; } catch (e) { return false; }
  }
  if (_inMemory) { _inMemory.delete(key); return true; }
  return false;
}
