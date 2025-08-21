Security Alert Backend — API Summary

This document lists the current HTTP API endpoints implemented in the project and short descriptions + example requests. Use the Swagger UI at /api/docs/ui for interactive testing; raw spec at /api/openapi.json.

Base URL (dev): http://localhost:3002/api

Health
- GET /healthz
  - Purpose: simple service health check
  - Payload: none
  - Serves: API gateway / root service health
  - Example: curl http://localhost:3002/api/healthz

Ingestion
- POST /ingestion/raw
  - Purpose: accept raw alert JSON from collectors or integrations
  - Payload: { id: string, payload: object }
  - Serves: Ingestion component — persists raw payload to object store (MinIO) and records metadata in ingestion repo
  - Example:
    curl -X POST http://localhost:3002/api/ingestion/raw -H 'Content-Type: application/json' -d '{"id":"alert-123","payload":{"message":"..."}}'

- GET /ingestion/raw-url
  - Purpose: return presigned URL for uploading large raw payloads
  - Payload: none (query params optional)
  - Serves: Ingestion component — provides upload handoff to object store

Normalization
- POST /normalization/{id}/normalized
  - Purpose: submit a normalized alert for the given id (OCSF-like normalized schema)
  - Payload: Normalized object (see components.schemas in OpenAPI): { original: object, mappings: array, normalized: { severity?, timestamp?, ... } }
  - Serves: Normalization component — stores normalized representation in normalization repo (ClickHouse / in-memory for dev)
  - Example:
    curl -X POST http://localhost:3002/api/normalization/alert-123/normalized -H 'Content-Type: application/json' -d '{"original":{},"mappings":[],"normalized":{"severity":"high","timestamp":"2025-08-17T12:00:00Z"}}'

- POST /normalization/normalize/trigger/{id}
  - Purpose: trigger normalization worker/process for an alert id
  - Payload: none (id in path)
  - Serves: Normalization component (job trigger / poller)

Embeddings
- POST /embeddings/{id}/embedding
  - Purpose: accept an embedding vector for an alert and persist it
  - Payload: { vector: number[], dimension?: number }
  - Serves: Embeddings component — persists to ClickHouse (`alerts_embeddings`) via `vector` client and notifies similarity service to add to index
  - Example:
    curl -X POST http://localhost:3002/api/embeddings/alert-123/embedding -H 'Content-Type: application/json' -d '{"vector":[0.12,-0.34,0.56],"dimension":3}'

- GET /embeddings/{id}/similar?k=5
  - Purpose: return similar alerts for the given alert id using the similarity (HNSW) service
  - Payload: none (path + optional query k)
  - Serves: Embeddings + Similarity components — embeddingsRepo will fetch stored embedding and call the similarity service (HTTP proxy) which hosts the HNSW index
  - Example:
    curl http://localhost:3002/api/embeddings/alert-123/similar?k=5

Triage
- POST /triage/{id}/score/triage
  - Purpose: compute triage S0 score and routing decision for the alert
  - Payload: optional { severity: "high" } to override normalized severity
  - Serves: Triage component — reads normalized alert (normalizationRepo), calls embeddingsRepo -> similarity service, computes S0 combining similarity, severity, and recency, and returns routing decision (verdict vs ml)
  - Example:
    curl -X POST http://localhost:3002/api/triage/alert-123/score/triage -H 'Content-Type: application/json' -d '{"severity":"high"}'
  - Response: { id, s0: number, decision: { route: string, s1: number } }

ML / LLM / Verdicts / Response (stubs)
- POST /ml/{id}/agent-output
  - Purpose: submit a single ML agent output for alert id
  - Payload: { agent: string, score: number, metadata?: object }
  - Serves: ML pipeline (agent ingestion)

- POST /ml/{id}/aggregate-score
  - Purpose: submit aggregated ML pipeline score
  - Payload: { combined_score: number, weights?: object }
  - Serves: ML aggregator

- POST /llm/{id}/llm-result
  - Purpose: submit LLM investigation output
  - Payload: { summary: string, score?: number }
  - Serves: LLM investigator component

- POST /verdicts/{id}/verdict
  - Purpose: submit final verdict for alert (TP/FP/ESCALATE)
  - Payload: { classification: "TP"|"FP"|"ESCALATE", confidence: number, notes?: string }
  - Serves: Verdicts store / audit

- GET /verdicts/{id}/verdicts
  - Purpose: list verdicts for an alert id
  - Payload: none
  - Serves: Verdicts query API

- POST /response/{id}/response-action
  - Purpose: execute or schedule an automatic response action
  - Payload: { action: string, target: object, parameters?: object }
  - Serves: Response automation controller (MCP stub)

- POST /response/{id}/response-result
  - Purpose: report result of response action
  - Payload: { status: string, details?: object }
  - Serves: Response audit log

Tasks
- POST /tasks
  - Purpose: create a tracking task
  - Payload: { title: string, assignee?: string, meta?: object }
  - Serves: Task tracking helper component

- GET /tasks
  - Purpose: list tasks
  - Payload: none
  - Serves: Task listing

Admin / Operator endpoints
- GET /admin/export
  - Purpose: export helper (dev stub)
  - Payload: none
  - Serves: admin/export helper

- POST /admin/:id/export-ready
  - Purpose: mark export ready
  - Payload: none
  - Serves: admin/export flow

- GET /admin/config/thresholds
  - Purpose: retrieve runtime triage thresholds/config
  - Payload: none
  - Serves: admin/config

- PATCH /admin/config/thresholds
  - Purpose: update thresholds/config
  - Payload: partial thresholds object
  - Serves: admin/config manager

- POST /admin/embeddings/build-index
  - Purpose: instruct similarity service to build or rebuild HNSW index from ClickHouse embeddings
  - Payload: { limit?: integer }
  - Serves: Admin operator -> triggers similarity service which reads ClickHouse and builds HNSW index
  - Example:
    curl -X POST http://localhost:3002/api/admin/embeddings/build-index -H 'Content-Type: application/json' -d '{"limit":10000}'

- POST /admin/embeddings/search
  - Purpose: proxy search to similarity service for debugging (vector or text)
  - Payload: { vector?: number[], text?: string, top_k?: number }
  - Serves: Admin debug tool -> proxies to similarity service
  - Example (vector search):
    curl -X POST http://localhost:3002/api/admin/embeddings/search -H 'Content-Type: application/json' -d '{"vector":[0.12,-0.34,0.56],"top_k":5}'

Observability
- GET /api/admin/metrics
  - Purpose: expose runtime metrics (Prometheus style in dev)
  - Payload: none
  - Serves: Observability / metrics scraping

- GET /api/admin/healthz
  - Purpose: admin health endpoint
  - Payload: none
  - Serves: Admin health check

Notes and operational tips
- The triage S0 computation depends on: normalized alert (timestamp + severity) + similarity results from the similarity service (HNSW). Ensure the similarity service is running and SIMILARITY_URL points to it (default http://localhost:8001).
- ClickHouse must be reachable at CLICKHOUSE_URL (default http://localhost:8123) for embeddings persistence and admin build-index.
- Swagger UI: http://localhost:3002/api/docs/ui — the OpenAPI spec includes examples and can be used to test endpoints.

If you want, I can:
- Convert this Markdown into a proper .docx (real Word file) and attach it here, or generate a PDF.
- Expand examples with full request/response payloads for specific endpoints.

## Key JSON Schemas (examples)

### Normalized (example)
```json
{
  "id": "alert-123",
  "original": { "source": "syslog", "raw": { /* original payload */ } },
  "mappings": [ { "field": "host", "value": "host-1" } ],
  "normalized": {
    "severity": "high",
    "timestamp": "2025-08-17T12:00:00Z",
    "title": "Failed SSH login",
    "description": "Multiple failed SSH logins from 10.0.0.1",
    "observables": [{ "type": "ip", "value": "10.0.0.1" }],
    "metadata": { "sensor": "ossec", "facility": "auth" }
  }
}
```

Fields of note:
- id: alert identifier (string)
- original: raw payload and source-specific fields
- mappings: optional helper mapping entries produced by normalizer
- normalized: canonical fields consumed by triage/ML (severity, timestamp, title, observables, metadata)

---

### EmbeddingRequest (example)
```json
{
  "vector": [0.123, -0.456, 0.789, ...],
  "dimension": 768,
  "meta": { "encoder": "sentence-transformers/all-MiniLM-L6-v2", "created_by": "ingestion-worker" }
}
```

Notes:
- vector: array of floats (embedding). The repo stores this in `alerts_embeddings.vector`.
- dimension: optional integer; if omitted the server may infer from vector.length.
- meta: optional object with provenance (encoder model, source, etc.)

---

### Triage Decision (response example)
```json
{
  "id": "alert-123",
  "s0": 82,
  "decision": {
    "route": "verdict",
    "s1": 82,
    "reason": {
      "similarity_mean": 0.88,
      "severity_base": 85,
      "recency_factor": 1.0
    }
  }
}
```

Notes:
- s0: primary triage score (0-100)
- decision.route: routing target (e.g., "verdict" or "ml")
- decision.s1: score forwarded to downstream (same as s0 in simple setup)
- decision.reason: optional breakdown used for debugging and audits

If you want, I can also embed the full JSON Schema (OpenAPI components) here or add example validation snippets for consumers.

## Request payload examples (copy/paste)

### Ingestion - POST /ingestion/raw
Request body (JSON):
```json
{
  "id": "alert-123",
  "payload": {
    "message": "User login failed",
    "source": "syslog",
    "timestamp": "2025-08-17T12:01:00Z",
    "details": { "user": "alice", "ip": "10.0.0.1", "port": 22 }
  }
}
```

### Normalization - POST /normalization/{id}/normalized
Request body (JSON):
```json
{
  "id": "alert-123",
  "original": { "source": "syslog", "raw": { "msg": "Failed SSH" } },
  "mappings": [{ "field": "host", "value": "host-1" }],
  "normalized": {
    "severity": "high",
    "timestamp": "2025-08-17T12:00:00Z",
    "title": "Failed SSH login",
    "description": "Multiple failed SSH logins from 10.0.0.1",
    "observables": [{ "type": "ip", "value": "10.0.0.1" }],
    "metadata": { "sensor": "ossec", "facility": "auth" }
  }
}
```

### Normalization trigger - POST /normalization/normalize/trigger/{id}
Request: none (path param only)

### Embeddings - POST /embeddings/{id}/embedding
Request body (JSON):
```json
{
  "vector": [0.123, -0.456, 0.789, 0.001, -0.002],
  "dimension": 5,
  "meta": { "encoder": "sentence-transformers/all-MiniLM-L6-v2", "created_by": "ingestion-worker" }
}
```

### Embeddings similar - GET /embeddings/{id}/similar?k=5
Request: none (path + query)

### Triage - POST /triage/{id}/score/triage
Request body (JSON) optional override:
```json
{ "severity": "high" }
```

### ML agent output - POST /ml/{id}/agent-output
Request body (JSON):
```json
{
  "agent": "anomaly-detector-v1",
  "score": 0.72,
  "metadata": { "window": "2025-08-17T11:30:00Z/2025-08-17T12:00:00Z" }
}
```

### ML aggregate - POST /ml/{id}/aggregate-score
Request body (JSON):
```json
{
  "combined_score": 78,
  "weights": { "anomaly": 0.6, "heuristic": 0.4 }
}
```

### LLM result - POST /llm/{id}/llm-result
Request body (JSON):
```json
{
  "summary": "LLM found evidence of credential stuffing across multiple hosts",
  "score": 0.85
}
```

### Verdict - POST /verdicts/{id}/verdict
Request body (JSON):
```json
{
  "classification": "TP",
  "confidence": 0.95,
  "notes": "Confirmed by SOC analyst"
}
```

### Response action - POST /response/{id}/response-action
Request body (JSON):
```json
{
  "action": "block_ip",
  "target": { "ip": "10.0.0.1" },
  "parameters": { "duration_minutes": 60 }
}
```

### Response result - POST /response/{id}/response-result
Request body (JSON):
```json
{ "status": "success", "details": { "action_id": "act-456", "applied_at": "2025-08-17T12:05:00Z" } }
```

### Tasks - POST /tasks
Request body (JSON):
```json
{ "title": "Investigate alert-123", "assignee": "alice", "meta": { "priority": "high" } }
```

### Admin - POST /admin/embeddings/build-index
Request body (JSON):
```json
{ "limit": 10000 }
```

### Admin - POST /admin/embeddings/search (vector)
Request body (JSON):
```json
{ "vector": [0.123, -0.456, 0.789], "top_k": 5 }
```

### Admin - POST /admin/embeddings/search (text)
Request body (JSON):
```json
{ "text": "failed login from 10.0.0.1", "top_k": 5 }
```

### Admin config patch - PATCH /admin/config/thresholds
Request body (JSON) example:
```json
{ "triage_threshold": 79, "escalation_threshold": 90 }
```

### Notes
- Dates should be RFC3339 (ISO 8601) strings.
- Embedding vectors should match the dimension expected by the similarity index; include `dimension` or ensure the index supports variable length (MVP uses fixed-length vectors).
- Use Swagger UI at /api/docs/ui to load these request examples into the editor for quick testing.

## Response payload examples (copy/paste)

### Ingestion - POST /ingestion/raw
Example success response (201):
```json
{
  "id": "alert-123",
  "status": "created",
  "location": "/objects/raw/alert-123.json",
  "received_at": "2025-08-17T12:01:05Z"
}
```

### Normalization - POST /normalization/{id}/normalized
Example success response (200):
```json
{
  "id": "alert-123",
  "status": "normalized",
  "stored_at": "2025-08-17T12:02:00Z"
}
```

### Embeddings - POST /embeddings/{id}/embedding
Example success response (200):
```json
{
  "ok": true,
  "embedding_id": "emb-789",
  "alert_id": "alert-123",
  "created_at": "2025-08-17T12:03:00Z"
}
```

### Embeddings similar - GET /embeddings/{id}/similar?k=5
Example response (200):
```json
[
  { "alert_id": "alert-456", "score": 0.92, "alpha_id": "alpha-1" },
  { "alert_id": "alert-789", "score": 0.88, "alpha_id": "alpha-2" }
]
```

### Triage - POST /triage/{id}/score/triage
Example response (200):
```json
{
  "id": "alert-123",
  "s0": 82,
  "decision": {
    "route": "verdict",
    "s1": 82,
    "reason": {
      "similarity_mean": 0.88,
      "severity_base": 85,
      "recency_factor": 1.0
    }
  }
}
```

### Admin - POST /admin/embeddings/build-index
Example response (200):
```json
{ "ok": true, "out": { "indexed": 12345, "duration_ms": 45210 } }
```

### Admin - POST /admin/embeddings/search
Example response (200):
```json
{ "ok": true, "out": { "results": [ { "alert_id": "alert-456", "score": 0.92, "alpha_id": "alpha-1" } ] } }
```

If you want these exact responses added as `examples` in `openapi.json` for each path, I can add them next so Swagger shows both request and response examples.

