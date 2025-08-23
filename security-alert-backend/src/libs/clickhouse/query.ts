import config from './index';

async function getFetch() {
  if (typeof fetch !== 'undefined') return (globalThis as any).fetch.bind(globalThis);
  try {
    // @ts-ignore
    const nf: any = await import('node-fetch');
    return (nf && (nf.default || nf)) as any;
  } catch (err) {
    throw new Error('fetch is not available. Please run on Node 18+ or install node-fetch');
  }
}

export async function querySQL(sql: string) {
  const fetchFn = await getFetch();
  const url = (config && (config.url as string)) || process.env.CLICKHOUSE_URL || 'http://localhost:8123';
  const headers: any = { 'Content-Type': 'text/plain' };
  if ((config as any).user && (config as any).password) {
    const token = Buffer.from(`${(config as any).user}:${(config as any).password}`).toString('base64');
    headers.Authorization = `Basic ${token}`;
  }
  const controller = new AbortController();
  const timeoutMs = 10000; // 10s
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  let res: any;
  try {
    res = await fetchFn(url, { method: 'POST', headers, body: sql, signal: controller.signal });
  } catch (err: any) {
    clearTimeout(timeout);
    throw new Error(`ClickHouse fetch failed to ${url}: ${err && err.message ? err.message : err}`);
  }
  clearTimeout(timeout);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`ClickHouse query error ${res.status} (${url}): ${text}`);
  }
  const txt = await res.text();
  // ClickHouse returns tabular text by default; request JSONEachRow by appending FORMAT JSON
  try {
    return JSON.parse(txt);
  } catch (e) {
    // fallback: try to parse lines of JSON
    return txt.split('\n').filter(Boolean).map((l: any) => {
      try { return JSON.parse(l); } catch { return l; }
    });
  }
}

export default { querySQL };
