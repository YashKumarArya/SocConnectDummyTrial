async function getFetch() {
  // prefer global fetch (Node 18+), otherwise dynamic import
  // @ts-ignore
  if (typeof globalThis.fetch === 'function') return globalThis.fetch
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  const nf = await import('node-fetch')
  return nf.default || nf
}

const SIM_URL = process.env.SIMILARITY_URL || 'http://localhost:8001'

export async function buildIndex(limit = 10000) {
  const fetcher = await getFetch()
  const url = `${SIM_URL}/build-index`
  const res = await fetcher(url, { method: 'POST', body: JSON.stringify({ limit }), headers: { 'Content-Type': 'application/json' } })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`similarity build failed: ${res.status} ${res.statusText} ${text}`)
  }
  return res.json()
}

export async function searchByVector(vector: number[], top_k = 10) {
  const fetcher = await getFetch()
  const url = `${SIM_URL}/search`
  const res = await fetcher(url, { method: 'POST', body: JSON.stringify({ vector, top_k }), headers: { 'Content-Type': 'application/json' } })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`similarity search failed: ${res.status} ${res.statusText} ${text}`)
  }
  return res.json()
}

export async function searchByText(text: string, top_k = 10) {
  const fetcher = await getFetch()
  const url = `${SIM_URL}/search`
  const res = await fetcher(url, { method: 'POST', body: JSON.stringify({ text, top_k }), headers: { 'Content-Type': 'application/json' } })
  if (!res.ok) {
    const textResp = await res.text().catch(() => '')
    throw new Error(`similarity search failed: ${res.status} ${res.statusText} ${textResp}`)
  }
  return res.json()
}

export async function addEmbedding(alpha_id: string, alert_id: string, vector: number[], embedding_id?: string) {
  const fetcher = await getFetch()
  const url = `${SIM_URL}/add-embedding`
  const body = { alpha_id, alert_id, embedding_id, vector }
  const res = await fetcher(url, { method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' } })
  if (!res.ok) {
    const textResp = await res.text().catch(() => '')
    throw new Error(`similarity add-embedding failed: ${res.status} ${res.statusText} ${textResp}`)
  }
  return res.json()
}
