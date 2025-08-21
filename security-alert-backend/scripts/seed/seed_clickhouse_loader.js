/*
Simple seed loader that posts JSONEachRow payloads to ClickHouse HTTP endpoint.
It reads the samples defined inline (same as the example generator) and posts to alerts_raw and alerts_normalized.
Usage: node scripts/seed/seed_clickhouse_loader.js
Set CLICKHOUSE_URL env var if not http://localhost:8123
*/
const fetch = require('node-fetch');

const CLICKHOUSE_URL = process.env.CLICKHOUSE_URL || 'http://localhost:8123';

const samples = [
  // SentinelOne EDR example
  {
    alpha_id: 'alpha-001',
    alert_id: 's1-1001',
    vendor: 'SentinelOne',
    product: 'EDR',
    timestamp: '2025-08-16T12:34:56.000Z',
    raw: {
      id: 's1-1001',
      vendor: 'SentinelOne',
      product: 'EDR',
      event: 'threat-detected',
      severity: 'high',
      source: { ip: '203.0.113.45', hostname: 'host-1' },
      file: { name: 'evil.exe', hash: 'abcd1234' }
    }
  },
  // Firewall IPS example
  {
    alpha_id: 'alpha-002',
    alert_id: 'fw-2023',
    vendor: 'SomeFirewall',
    product: 'IPS',
    timestamp: '2025-08-16T13:00:00.000Z',
    raw: {
      id: 'fw-2023',
      vendor: 'SomeFirewall',
      product: 'IPS',
      rule: 'SQLi',
      severity: 'medium',
      src_ip: '198.51.100.10',
      dst_ip: '10.0.0.5'
    }
  },
  // Microsoft Exchange Email example
  {
    alpha_id: 'alpha-003',
    alert_id: 'ex-501',
    vendor: 'Microsoft',
    product: 'Exchange',
    timestamp: '2025-08-16T14:15:00.000Z',
    raw: {
      id: 'ex-501',
      vendor: 'Microsoft',
      product: 'Exchange',
      event: 'phishing-email',
      email: { from: 'bad@attacker.test', to: 'user@org.test', subject: 'Urgent: Verify' }
    }
  }
];

async function postJSON(sql, rows) {
  const body = rows.map((r) => JSON.stringify(r)).join('\n');
  const res = await fetch(CLICKHOUSE_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: `${sql}\n${body}\n`
  });
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`ClickHouse error ${res.status}: ${txt}`);
  }
  return true;
}

async function main() {
  // Insert into alerts_raw
  const sqlRaw = "INSERT INTO security_alerts.alerts_raw (alpha_id, alert_id, vendor, product, received_at, raw) FORMAT JSONEachRow";
  const rawRows = samples.map((s) => ({ alpha_id: s.alpha_id, alert_id: s.alert_id, vendor: s.vendor, product: s.product, received_at: s.timestamp, raw: s.raw }));

  // Insert into alerts_normalized
  const sqlNorm = "INSERT INTO security_alerts.alerts_normalized (alpha_id, alert_id, vendor, product, severity, category, event_action, source_ip, dest_ip, src_username, dest_username, file_name, file_hash, url, email_from, email_to, email_subject, timestamp, normalized, embedding_id) FORMAT JSONEachRow";
  const normRows = samples.map((s) => {
    return {
      alpha_id: s.alpha_id,
      alert_id: s.alert_id,
      vendor: s.vendor,
      product: s.product,
      severity: s.raw.severity || 'unknown',
      category: s.raw.event || null,
      event_action: s.raw.event || null,
      source_ip: s.raw.source?.ip || s.raw.src_ip || null,
      dest_ip: s.raw.destination?.ip || s.raw.dst_ip || null,
      src_username: null,
      dest_username: null,
      file_name: s.raw.file?.name || null,
      file_hash: s.raw.file?.hash || null,
      url: s.raw.url || null,
      email_from: s.raw.email?.from || null,
      email_to: s.raw.email?.to || null,
      email_subject: s.raw.email?.subject || null,
      timestamp: s.timestamp,
      normalized: JSON.stringify(s.raw),
      embedding_id: null
    };
  });

  try {
    console.log('posting raw...');
    await postJSON(sqlRaw, rawRows);
    console.log('raw posted');
  } catch (err) {
    console.error('raw post failed', err);
  }

  try {
    console.log('posting normalized...');
    await postJSON(sqlNorm, normRows);
    console.log('normalized posted');
  } catch (err) {
    console.error('normalized post failed, writing to DLQ');
    // write to DLQ table
    try {
      const dlqSql = "INSERT INTO security_alerts.alerts_normalized_dlq (alpha_id, alert_id, vendor, product, normalized, error_message, attempts, last_error_at) FORMAT JSONEachRow";
      const dlqRows = normRows.map((r) => ({ alpha_id: r.alpha_id, alert_id: r.alert_id, vendor: r.vendor, product: r.product, normalized: JSON.stringify(r), error_message: String(err), attempts: 1, last_error_at: new Date().toISOString() }));
      await postJSON(dlqSql, dlqRows);
      console.log('written to dlq');
    } catch (e) {
      console.error('failed to write to dlq', e);
    }
  }
}

main().catch((e) => {
  console.error('fatal', e);
  process.exit(1);
});
