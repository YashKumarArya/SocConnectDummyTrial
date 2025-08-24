import { normalizeHybrid } from '../../common/normalizer.hybrid';
import clickhouse from '../../libs/clickhouse/client';

export type AlertsOcsfV4Row = any;

export function normalizeToV4(raw: any, opts: any): AlertsOcsfV4Row {
  // use normalizeHybrid to produce nested OCSF-like object, then return as-is for v4 conversion elsewhere
  return normalizeHybrid(raw, {}, undefined);
}

export async function insertAlertsV4(rows: AlertsOcsfV4Row[]) {
  // best-effort: if clickhouse client exists, write JSONEachRow directly
  if (!rows || rows.length === 0) return;
  const body = 'INSERT INTO soc.edr_alerts_ocsf FORMAT JSONEachRow\n' + rows.map((r) => JSON.stringify(r)).join('\n');
  const cfg: any = (clickhouse as any).config || (clickhouse as any);
  const url = cfg.url;
  if (!url) throw new Error('CLICKHOUSE_URL not configured');
  const fetchFn = (globalThis as any).fetch || (async () => { const nf:any = await import('node-fetch'); return nf.default || nf; })();
  const token = cfg.user && cfg.password ? Buffer.from(`${cfg.user}:${cfg.password}`).toString('base64') : null;
  const headers: any = { 'Content-Type': 'text/plain' };
  if (token) headers.Authorization = `Basic ${token}`;
  const fn: any = await fetchFn;
  const res = await fn(url, { method: 'POST', headers, body });
  if (!res.ok) throw new Error(`insertAlertsV4 failed ${res.status}: ${await res.text()}`);
}
