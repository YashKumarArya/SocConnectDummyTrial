// Lightweight vector client for ClickHouse (inserts + simple reads)
import { randomUUID } from 'crypto'

async function getFetch() {
  // runtime fetch resolver: prefer global fetch (Node 18+), otherwise dynamic import
  // @ts-ignore
  if (typeof globalThis.fetch === 'function') return globalThis.fetch
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore: optional dynamic import for node-fetch
  const nf = await import('node-fetch')
  return nf.default || nf
}

const CLICKHOUSE_URL = process.env.CLICKHOUSE_URL || 'http://localhost:8123'

export type EmbeddingRow = {
  alpha_id: string
  alert_id: string
  embedding_id: string
  vector: number[]
  dimension: number
  created_at: string
}

export async function insertEmbedding(row: Omit<EmbeddingRow, 'created_at'|'embedding_id'> & { embedding_id?: string }) {
  const fetcher = await getFetch()
  const embedding_id = row.embedding_id || randomUUID()
  const payload = {
    alpha_id: row.alpha_id,
    alert_id: row.alert_id,
    embedding_id,
    vector: row.vector,
    dimension: row.dimension || row.vector.length,
    created_at: new Date().toISOString(),
  }

  const sql = `INSERT INTO alerts_embeddings (alpha_id, alert_id, embedding_id, vector, dimension, created_at) FORMAT JSONEachRow`
  const body = JSON.stringify(payload)
  const res = await fetcher(CLICKHOUSE_URL, { method: 'POST', body: sql + '\n' + body })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`clickhouse insert failed: ${res.status} ${res.statusText} ${text}`)
  }
  return embedding_id
}

// fetch recent embeddings (simple approach for MVP). Use LIMIT to avoid huge reads.
export async function fetchEmbeddings(limit = 10000) : Promise<EmbeddingRow[]> {
  const fetcher = await getFetch()
  const sql = `SELECT alpha_id, alert_id, embedding_id, vector, dimension, created_at FROM alerts_embeddings ORDER BY created_at DESC LIMIT ${limit} FORMAT JSONEachRow`
  const url = `${CLICKHOUSE_URL}?query=${encodeURIComponent(sql)}`
  const res = await fetcher(url)
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`clickhouse select failed: ${res.status} ${res.statusText} ${text}`)
  }
  const text = await res.text()
  if (!text) return []
  // parse JSONEachRow: one JSON object per line
  const rows: EmbeddingRow[] = text.split('\n').filter(Boolean).map((line: string) => JSON.parse(line) as EmbeddingRow)
  return rows
}

export async function fetchEmbeddingById(embedding_id: string) {
  const fetcher = await getFetch()
  const sql = `SELECT alpha_id, alert_id, embedding_id, vector, dimension, created_at FROM alerts_embeddings WHERE embedding_id = '${embedding_id}' LIMIT 1 FORMAT JSONEachRow`
  const url = `${CLICKHOUSE_URL}?query=${encodeURIComponent(sql)}`
  const res = await fetcher(url)
  if (!res.ok) throw new Error(`clickhouse select failed: ${res.status}`)
  const text = await res.text()
  const line = text.split('\n').find(Boolean)
  if (!line) return null
  return JSON.parse(line) as EmbeddingRow
}
