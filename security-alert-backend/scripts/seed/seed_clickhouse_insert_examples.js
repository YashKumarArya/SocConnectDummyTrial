/*
Simple Node script to generate INSERT examples for the ClickHouse tables from sample JSON alerts.
Run: node scripts/seed/seed_clickhouse_insert_examples.js > /tmp/clickhouse_inserts.sql
This produces INSERT INTO ... VALUES (...) statements for alerts_raw and alerts_normalized.
*/
const fs = require('fs');

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

function sqlEscape(s) {
  if (s === null || s === undefined) return 'NULL';
  return "'" + String(s).replace(/'/g, "\\'") + "'";
}

const out = [];

// alerts_raw inserts
out.push('-- INSERTS for alerts_raw');
out.push('INSERT INTO security_alerts.alerts_raw (alpha_id, alert_id, vendor, product, received_at, raw) VALUES');
out.push(
  samples
    .map((s) => {
      const rawStr = JSON.stringify(s.raw).replace(/'/g, "\\'");
      return `(${sqlEscape(s.alpha_id)}, ${sqlEscape(s.alert_id)}, ${sqlEscape(s.vendor)}, ${sqlEscape(
        s.product
      )}, ${sqlEscape(s.timestamp)}, ${sqlEscape(rawStr)})`;
    })
    .join(',\n') + ';'
);

// alerts_normalized inserts (minimal normalized columns + full normalized JSON)
out.push('\n-- INSERTS for alerts_normalized');
out.push('INSERT INTO security_alerts.alerts_normalized (alpha_id, alert_id, vendor, product, severity, category, event_action, source_ip, dest_ip, src_username, dest_username, file_name, file_hash, url, email_from, email_to, email_subject, timestamp, normalized, embedding_id) VALUES');
out.push(
  samples
    .map((s) => {
      const norm = {
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
        normalized: JSON.stringify(s.raw).replace(/'/g, "\\'"),
        embedding_id: null
      };
      return `(${sqlEscape(norm.alpha_id)}, ${sqlEscape(norm.alert_id)}, ${sqlEscape(norm.vendor)}, ${sqlEscape(norm.product)}, ${sqlEscape(norm.severity)}, ${sqlEscape(norm.category)}, ${sqlEscape(norm.event_action)}, ${sqlEscape(norm.source_ip)}, ${sqlEscape(norm.dest_ip)}, ${sqlEscape(norm.src_username)}, ${sqlEscape(norm.dest_username)}, ${sqlEscape(norm.file_name)}, ${sqlEscape(norm.file_hash)}, ${sqlEscape(norm.url)}, ${sqlEscape(norm.email_from)}, ${sqlEscape(norm.email_to)}, ${sqlEscape(norm.email_subject)}, ${sqlEscape(norm.timestamp)}, ${sqlEscape(norm.normalized)}, ${sqlEscape(norm.embedding_id)})`;
    })
    .join(',\n') + ';'
);

console.log(out.join('\n'));
