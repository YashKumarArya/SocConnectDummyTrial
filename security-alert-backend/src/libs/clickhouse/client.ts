import config from './index';

const MAX_BATCH = 100;
const DEFAULT_RETRIES = 3;

function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
}

async function getFetch() {
  if (typeof fetch !== 'undefined') {
    // use global fetch (Node 18+ or browser)
    return (globalThis as any).fetch.bind(globalThis);
  }

  try {
    // dynamic import so dependency is optional during dev
    // @ts-ignore: optional dependency may not be installed in all environments
    const nf: any = await import('node-fetch');
    return (nf && (nf.default || nf)) as any;
  } catch (err) {
    throw new Error('fetch is not available. Please run on Node 18+ or install node-fetch');
  }
}

async function postSQL(sql: string, body?: string, retries = DEFAULT_RETRIES) {
  const fetchFn = await getFetch();

  try {
    const res = await fetchFn(config.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body ? `${body}\n` : sql
    });

    if (!res.ok) {
      const txt = await res.text();
      const err = new Error(`ClickHouse error ${res.status}: ${txt}`);
      // simple retry logic for 5xx
      if (res.status >= 500 && retries > 0) {
        await sleep(2 ** (DEFAULT_RETRIES - retries) * 200);
        return postSQL(sql, body, retries - 1);
      }
      throw err;
    }

    return true;
  } catch (err: any) {
    if (retries > 0) {
      await sleep(200 * (DEFAULT_RETRIES - retries + 1));
      return postSQL(sql, body, retries - 1);
    }
    throw err;
  }
}

// Helper: safely get nested properties using path array or dot string
function getPath(obj: any, path: string | string[], def: any = undefined) {
  if (!obj) return def;
  const parts = Array.isArray(path) ? path : path.split('.');
  let cur = obj;
  for (const p of parts) {
    if (cur == null) return def;
    cur = cur[p];
  }
  return cur === undefined ? def : cur;
}

function normalizeTimestamp(val: any) {
  if (!val) return null;
  const d = new Date(val);
  if (isNaN(d.getTime())) return null;
  return d.toISOString();
}

export async function insertNormalized(rows: any[]) {
  if (!rows || rows.length === 0) return 0;

  // map rows to the expanded ClickHouse columns using the normalized object (OCSF mapping)
  const payloads = rows.map((r) => {
    const n = r.normalized || {};

    // actor host
    const host_id = getPath(n, ['actor', 'host', 'id'], getPath(r, 'host_id', null));
    const host_hostname = getPath(n, ['actor', 'host', 'hostname'], getPath(n, ['actor', 'host', 'name'], getPath(r, 'host_hostname', null)));
    const host_ip = getPath(n, ['actor', 'host', 'ip'], getPath(r, 'host_ip', null));
    const host_os_name = getPath(n, ['actor', 'host', 'os', 'name'], null);
    const host_os_version = getPath(n, ['actor', 'host', 'os', 'version'], null);
    const host_group_name = getPath(n, ['actor', 'host', 'group', 'name'], null);

    // user
    const user_name = getPath(n, ['actor', 'user', 'name'], getPath(n, ['actor', 'process', 'user', 'name'], getPath(r, 'user_name', null)));
    const user_upn = getPath(n, ['actor', 'user', 'upn'], null);

    // process
    const process_name = getPath(n, ['actor', 'process', 'name'], null);
    const process_mitigation_status = getPath(n, ['actor', 'process', 'mitigation_status'], null);
    const process_initiated_by = getPath(n, ['actor', 'process', 'initiated_by'], null);
    const process_analyst_verdict = getPath(n, ['actor', 'process', 'analyst_verdict'], null);

    // file
    const file_path = getPath(n, ['actor', 'process', 'file', 'path'], null);
    const file_sha1 = getPath(n, ['actor', 'process', 'file', 'hashes', 'sha1'], null) || getPath(n, ['file', 'sha1'], null);
    const file_sha256 = getPath(n, ['actor', 'process', 'file', 'hashes', 'sha256'], null) || getPath(n, ['file', 'sha256'], null);
    const file_md5 = getPath(n, ['actor', 'process', 'file', 'hashes', 'md5'], null) || getPath(n, ['file', 'md5'], null);
    const file_size = getPath(n, ['actor', 'process', 'file', 'size'], null);
    const file_extension = getPath(n, ['actor', 'process', 'file', 'extension'], null);
    const file_extension_type = getPath(n, ['actor', 'process', 'file', 'extension_type'], null);
    const file_publisher = getPath(n, ['actor', 'process', 'signer', 'publisher'], null) || getPath(n, ['file', 'publisher'], null);

    // threat
    const threat_id = getPath(n, ['threat', 'id'], getPath(n, ['threatId'], null));
    const threat_name = getPath(n, ['threat', 'name'], getPath(n, ['threatName'], null));
    const threat_classification = getPath(n, ['threat', 'classification'], null);
    const threat_confidence = getPath(n, ['threat', 'confidence'], getPath(n, ['confidenceLevel'], null));
    const incident_status = getPath(n, ['status'], null) || getPath(n, ['threat', 'status'], null);
    const threat_mitigation_status = getPath(n, ['threat', 'mitigation_status'], null);
    const threat_storyline = getPath(n, ['threat', 'narrative'], getPath(n, ['threat', 'storyline'], null));

    // network interfaces (array -> JSON string)
    const networkInterfaces = getPath(n, ['actor', 'host', 'network_interfaces'], getPath(n, ['networkInterfaces'], null));
    const host_network_interfaces = networkInterfaces ? JSON.stringify(networkInterfaces) : null;

    // account
    const account_id = getPath(n, ['account', 'id'], null);
    const account_name = getPath(n, ['account', 'name'], null);
    const account_site_id = getPath(n, ['account', 'site', 'id'], null);
    const account_site_name = getPath(n, ['account', 'site', 'name'], null);

    // certificate
    const certificate_id = getPath(n, ['actor', 'process', 'signer', 'certificate', 'id'], null);
    const certificate_is_valid = getPath(n, ['actor', 'process', 'signer', 'certificate', 'is_valid'], null) ? 1 : 0;
    const certificate_publisher = getPath(n, ['actor', 'process', 'signer', 'publisher'], file_publisher);

    // common fields
    const source_ip = getPath(n, ['network', 'src_endpoint', 'ip'], getPath(n, ['source_ip'], getPath(r, 'source_ip', null)));
    const dest_ip = getPath(n, ['network', 'dst_endpoint', 'ip'], getPath(n, ['dest_ip'], getPath(r, 'dest_ip', null)));
    const src_username = getPath(n, ['actor', 'user', 'name'], getPath(r, 'src_username', null));
    const dest_username = getPath(n, ['dest_username'], null);
    const url = getPath(n, ['url'], null);
    const email_from = getPath(n, ['email', 'from'], null);
    const email_to = getPath(n, ['email', 'to'], null);
    const email_subject = getPath(n, ['email', 'subject'], null);

    const severity = getPath(n, ['severity'], getPath(n, ['event', 'severity'], null));
    const category = getPath(n, ['category'], getPath(n, ['event', 'type'], null));
    const event_action = getPath(n, ['action'], getPath(n, ['event', 'action'], null));

    const timestampRaw = getPath(n, ['timestamp'], getPath(r, 'timestamp', null));
    const timestamp = normalizeTimestamp(timestampRaw) || new Date().toISOString();

    return {
      alpha_id: r.alpha_id || r.alphaId || r.alpha || r.alpha || (r.alert_id || r.id) || 'unknown',
      alert_id: r.alert_id || r.id || null,
      vendor: r.vendor || null,
      product: r.product || null,

      severity,
      category,
      event_action,

      host_id,
      host_hostname,
      host_ip,
      host_os_name,
      host_os_version,
      host_group_name,

      user_name,
      user_upn,

      process_name,
      process_mitigation_status,
      process_initiated_by,
      process_analyst_verdict,

      file_path,
      file_sha1,
      file_sha256,
      file_md5,
      file_size,
      file_extension,
      file_extension_type,
      file_publisher,

      threat_id,
      threat_name,
      threat_classification,
      threat_confidence,
      incident_status,
      threat_mitigation_status,
      threat_storyline,

      host_network_interfaces,

      account_id,
      account_name,
      account_site_id,
      account_site_name,

      certificate_id,
      certificate_is_valid,
      certificate_publisher,

      source_ip,
      dest_ip,
      src_username,
      dest_username,
      url,
      email_from,
      email_to,
      email_subject,

      timestamp,
      normalized: typeof r.normalized === 'string' ? r.normalized : JSON.stringify(r.normalized || {}),
      embedding_id: r.embedding_id || null
    };
  });

  // chunk rows
  const chunks: any[][] = [];
  for (let i = 0; i < payloads.length; i += MAX_BATCH) {
    chunks.push(payloads.slice(i, i + MAX_BATCH));
  }

  for (const chunk of chunks) {
    const sql = `INSERT INTO security_alerts.alerts_normalized FORMAT JSONEachRow`;
    const body = chunk.map((r) => JSON.stringify(r)).join('\n');
    await postSQL(sql, body);
  }

  return rows.length;
}

/**
 * Insert rows into the DLQ table. Each row should be an object with keys matching the DLQ DDL.
 * The function will stringify normalized payloads where necessary.
 */
export async function insertDLQ(rows: any[], errorMessage?: string) {
  if (!rows || rows.length === 0) return 0;

  const payloads = rows.map((r) => {
    const n = r.normalized || {};
    const host_id = getPath(n, ['actor', 'host', 'id'], getPath(r, 'host_id', null));
    return {
      alpha_id: r.alpha_id || null,
      alert_id: r.alert_id || null,
      vendor: r.vendor || null,
      product: r.product || null,
      normalized: typeof r.normalized === 'string' ? r.normalized : JSON.stringify(r.normalized || {}),
      host_id,
      error_message: errorMessage || r.error_message || null,
      attempts: r.attempts ?? 1,
      last_error_at: r.last_error_at ?? new Date().toISOString()
    };
  });

  // chunk and post
  const chunks: any[][] = [];
  for (let i = 0; i < payloads.length; i += MAX_BATCH) {
    chunks.push(payloads.slice(i, i + MAX_BATCH));
  }

  for (const chunk of chunks) {
    const sql = `INSERT INTO security_alerts.alerts_normalized_dlq FORMAT JSONEachRow`;
    const body = chunk.map((r) => JSON.stringify(r)).join('\n');
    await postSQL(sql, body);
  }

  return rows.length;
}

export default { insertNormalized, insertDLQ };
