import { v4 as uuidv4 } from 'uuid';
import config from './index';

async function getFetch() {
  if (typeof fetch !== 'undefined') return (globalThis as any).fetch.bind(globalThis);
  // dynamic import to keep optional
  const nf: any = await import('node-fetch');
  return (nf && (nf.default || nf)) as any;
}

function toISO(d?: string | number | Date) {
  if (!d) return new Date().toISOString();
  const dt = new Date(d);
  if (isNaN(dt.getTime())) return new Date().toISOString();
  return dt.toISOString();
}

export async function insertAlertsRaw(alert: any) {
  const fetchFn = await getFetch();
  if (!alert) throw new Error('missing alert');

  const alphaId = alert.alpha_id || alert.alphaId || uuidv4();
  const alertId = alert.id || '';

  const row: any = {
    alpha_id: alphaId,
    alert_id: alertId,
    raw_alert: typeof alert === 'string' ? alert : JSON.stringify(alert),
    source_vendor: alert.source_vendor || alert.vendor || '',
    source_product: alert.source_product || alert.product || '',
    ingested_at: toISO(alert.ingested_at || alert.ingestedAt || new Date()),
    version: Math.floor(new Date((alert.ingested_at || alert.ingestedAt || new Date())).getTime() / 1000)
  };

  const body = `INSERT INTO soc.alerts_raw FORMAT JSONEachRow\n${JSON.stringify(row)}`;

  const res = await fetchFn(config.url, {
    method: 'POST',
    headers: (() => {
      const h: any = { 'Content-Type': 'text/plain' };
      if ((config as any).user && (config as any).password) {
        const token = Buffer.from(`${(config as any).user}:${(config as any).password}`).toString('base64');
        h.Authorization = `Basic ${token}`;
      }
      return h;
    })(),
    body
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`ClickHouse insert alerts_raw failed ${res.status}: ${text}`);
  }

  return alphaId;
}

export default { insertAlertsRaw };
