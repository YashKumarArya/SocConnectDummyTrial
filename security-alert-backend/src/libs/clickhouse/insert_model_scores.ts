import config from './index';

const MAX_BATCH = 100;

async function getFetch() {
  if (typeof fetch !== 'undefined') return (globalThis as any).fetch.bind(globalThis);
  const nf: any = await import('node-fetch');
  return (nf && (nf.default || nf)) as any;
}

function safeNumber(v: any) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

export type TriageAgent = {
  prediction?: {
    predicted_verdict?: string; // e.g. "Escalate"
    risk_score?: number; // e.g. 77.61955
    confidence?: number; // optional
  };
  metadata?: any;
  model_version?: string;
  timestamp?: string;
};

export type WideRow = {
  alert_id: string;
  alpha_id: string;
  ts?: string;

  // From triage (rule-based)
  rule_confidence: number;
  rule_verdict: string;
  rule_meta: string; // JSON string: triage.metadata

  // From supervisor/agents (optional fields)
  gnn_confidence?: number;
  gnn_verdict?: string;
  gnn_meta?: string;

  edr_score?: number;
  edr_verdict?: string;
  edr_meta?: string;

  supervisor_score?: number;
  supervisor_verdict?: string;
  supervisor_meta?: string;

  // Optional summary text
  summary?: string;
};

export function fromTriageToWideRow(
  alert_id: string,
  alpha_id: string,
  triage: TriageAgent,
  _opts?: { v4_fields_present?: number; v4_fields_total?: number; v4_schema_version?: string }
): WideRow {
  const rule_confidence = safeNumber(triage?.prediction?.confidence ?? 0);
  const rule_verdict = String(triage?.prediction?.predicted_verdict ?? '');
  const rule_meta = JSON.stringify(triage?.metadata ?? {});

  return {
    alert_id,
    alpha_id,
    rule_confidence,
    rule_verdict,
    rule_meta
  };
}

async function postSQL(sql: string, body?: string) {
  const fetchFn = await getFetch();
  const headers: any = { 'Content-Type': 'text/plain' };
  if (config.user && config.password) {
    const token = Buffer.from(`${config.user}:${config.password}`).toString('base64');
    headers.Authorization = `Basic ${token}`;
  }
  const bodyText = body ? `${sql}\n${body}\n` : `${sql}\n`;
  const res = await fetchFn(config.url, { method: 'POST', headers, body: bodyText });
  if (!res.ok) {
    const txt = await res.text().catch(() => '<no body>');
    throw new Error(`ClickHouse insert failed ${res.status}: ${txt}`);
  }
  return true;
}

export async function insertTriageWide(rows: WideRow[]) {
  if (!rows || rows.length === 0) return 0;

  const chunks: WideRow[][] = [];
  for (let i = 0; i < rows.length; i += MAX_BATCH) {
    chunks.push(rows.slice(i, i + MAX_BATCH));
  }

  for (const chunk of chunks) {
    // Let ClickHouse map JSON keys to columns; omitted fields take type defaults.
    const sql = `INSERT INTO soc.alert_model_scores_wide FORMAT JSONEachRow`;
    const body = chunk.map((r) => JSON.stringify(r)).join('\n');
    await postSQL(sql, body);
  }

  return rows.length;
}

export default { fromTriageToWideRow, insertTriageWide };
