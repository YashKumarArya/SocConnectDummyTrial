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

  gnn_score: number;
  gnn_confidence: number;
  gnn_verdict: string;

  ml_score: number;
  ml_confidence: number;
  ml_verdict: string;

  rule_score: number;
  rule_confidence: number;
  rule_verdict: string;

  meta: string;
};

export function fromTriageToWideRow(
  alert_id: string,
  alpha_id: string,
  triage: TriageAgent,
  opts?: { v4_fields_present?: number; v4_fields_total?: number; v4_schema_version?: string }
): WideRow {
  const rule_score = safeNumber(triage?.prediction?.risk_score ?? 0);
  const rule_confidence = safeNumber(triage?.prediction?.confidence ?? 0);
  const rule_verdict = String(triage?.prediction?.predicted_verdict ?? '');

  const metaObj: Record<string, any> = {
    ...(opts?.v4_fields_present != null && {
      v4_fields_present: opts.v4_fields_present,
      v4_fields_total: opts.v4_fields_total ?? 101,
      v4_schema_version: opts.v4_schema_version ?? 'v4',
      v4_coverage_pct:
        opts?.v4_fields_present != null && (opts?.v4_fields_total ?? 101) > 0
          ? +(((opts.v4_fields_present as number) / (opts.v4_fields_total ?? 101)) * 100).toFixed(2)
          : undefined
    }),
    triage_summary: {
      verdict: rule_verdict,
      risk_score: rule_score,
      model_version: triage.model_version ?? null,
      timestamp: triage.timestamp ?? null
    },
    agent1: triage?.metadata?.agent1_score ?? undefined,
    agent2: triage?.metadata?.agent2_score ?? undefined
  };

  return {
    alert_id,
    alpha_id,
    gnn_score: 0,
    gnn_confidence: 0,
    gnn_verdict: '',
    ml_score: 0,
    ml_confidence: 0,
    ml_verdict: '',
    rule_score,
    rule_confidence,
    rule_verdict,
    meta: JSON.stringify(metaObj)
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
    const sql = `INSERT INTO soc.alert_model_scores_wide FORMAT JSONEachRow`;
    const body = chunk.map((r) => JSON.stringify(r)).join('\n');
    await postSQL(sql, body);
  }

  return rows.length;
}

export default { fromTriageToWideRow, insertTriageWide };
