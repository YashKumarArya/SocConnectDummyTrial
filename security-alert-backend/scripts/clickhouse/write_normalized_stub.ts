/*
Small Node script (TypeScript) to write normalized rows to ClickHouse via HTTP API (stub).
This uses a runtime fetch resolver to support Node 18+ global fetch and optional node-fetch fallback.
Run with ts-node: npx ts-node scripts/clickhouse/write_normalized_stub.ts
*/

const CLICKHOUSE_URL = process.env.CLICKHOUSE_URL || 'http://localhost:8123';

async function getFetch() {
  if (typeof fetch !== 'undefined') return (globalThis as any).fetch.bind(globalThis);
  try {
    // @ts-ignore optional dependency
    const nf: any = await import('node-fetch');
    return (nf && (nf.default || nf)) as any;
  } catch (err) {
    throw new Error('fetch is not available. Please run on Node 18+ or install node-fetch');
  }
}

async function writeNormalized(row: any) {
  const fetchFn = await getFetch();
  const sql = `INSERT INTO security_alerts.alerts_normalized FORMAT JSONEachRow`;
  const body = JSON.stringify(row);
  const res = await fetchFn(CLICKHOUSE_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: `${body}\n`
  });
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`clickhouse write failed: ${res.status} ${txt}`);
  }
  return true;
}

async function main() {
  const sample = {
    alpha_id: 'alpha-001',
    alert_id: 's1-1001',
    vendor: 'SentinelOne',
    product: 'EDR',
    severity: 'high',
    category: 'threat-detected',
    event_action: 'threat-detected',
    source_ip: '203.0.113.45',
    dest_ip: null,
    src_username: null,
    dest_username: null,
    file_name: 'evil.exe',
    file_hash: 'abcd1234',
    url: null,
    email_from: null,
    email_to: null,
    email_subject: null,
    timestamp: '2025-08-16 12:34:56',
    normalized: { message: 'sample normalized payload' },
    embedding_id: null
  };

  try {
    await writeNormalized(sample);
    console.info('written');
  } catch (err: any) {
    console.error('error', err.message || err);
  }
}

main();
