ClickHouse schema — security_alerts

This document describes the ClickHouse table layout used by the project (DDL files are in `scripts/ddl/`). It is intended as reference for engineers and for wiring ETL/exports.

Overview
- Database: `security_alerts`
- Time columns use DateTime64(3) (milliseconds)
- Partition strategy: monthly (to keep partitions manageable) using `toYYYYMM(<time_col>)`
- Main tables:
  - `alerts_raw` — raw alert JSON and a few searchable columns
  - `alerts_normalized` — normalized OCSF-like alert columns + full normalized JSON and optional embedding reference
  - `alerts_embeddings` — embedding vectors (if stored in ClickHouse) and metadata
  - `alerts_normalized_dlq` — dead-letter queue for normalized rows that failed to persist

DDL files
- scripts/ddl/01_alerts_raw.sql — CREATE TABLE alerts_raw
- scripts/ddl/02_alerts_normalized.sql — CREATE TABLE alerts_normalized
- scripts/ddl/03_alerts_embeddings.sql — CREATE TABLE alerts_embeddings
- scripts/ddl/04_normalization_dlq.sql — CREATE TABLE alerts_normalized_dlq

Table: security_alerts.alerts_raw
- Purpose: store the original ingested payload (as JSON string) and a few indexed fields for quick lookup
- Columns:
  - alpha_id String — project alert id (primary external id)
  - alert_id String — vendor/local alert id
  - vendor String
  - product String
  - received_at DateTime64(3) DEFAULT now()
  - raw String — JSON payload as string
- Engine: MergeTree()
- Partition: toYYYYMM(received_at)
- Order by: (alpha_id, alert_id)
- Usage: keep raw payloads for forensic retrieval and re-normalization; considered immutable once saved

Table: security_alerts.alerts_normalized
- Purpose: normalized alerts for analytics, triage, ML and export
- Columns (recommended mapping):
  - alpha_id String
  - alert_id String
  - vendor String
  - product String
  - severity LowCardinality(String)
  - category LowCardinality(String)
  - event_action LowCardinality(String)
  - source_ip Nullable(String)
  - dest_ip Nullable(String)
  - src_username Nullable(String)
  - dest_username Nullable(String)
  - file_name Nullable(String)
  - file_hash Nullable(String)
  - url Nullable(String)
  - email_from Nullable(String)
  - email_to Nullable(String)
  - email_subject Nullable(String)
  - timestamp DateTime64(3)
  - normalized JSON — the full normalized object (stringified JSON OK)
  - embedding_id Nullable(String) — reference to vector store / embedding row
- Engine: ReplacingMergeTree()
  - Reason: allows re-ingestion/updates of normalized rows (replace by key) while keeping latest copy
- Partition: toYYYYMM(timestamp)
- Order by: (alpha_id, alert_id)
- Notes: use LowCardinality for categorical columns to reduce memory usage

Table: security_alerts.alerts_embeddings
- Purpose: store embeddings for alerts (optional — many systems store vectors externally)
- Columns:
  - alpha_id String
  - alert_id String
  - embedding_id String — identifier for the vector (could be same as alert_id or UUID)
  - vector Array(Float32)
  - dimension UInt32
  - created_at DateTime64(3) DEFAULT now()
- Engine: MergeTree()
- Partition: toYYYYMM(created_at)
- Order by: (alpha_id, alert_id, embedding_id)
- Notes: ClickHouse can store arrays of floats for simple similarity computations, but dedicated vector DB or FAISS is recommended for high-performance vector search. Use ClickHouse embeddings table for historic storage and small-scale similarity.

Table: security_alerts.alerts_normalized_dlq
- Purpose: capture normalized rows that failed to persist to `alerts_normalized` (errors, transient failures, schema mismatches)
- Columns:
  - alpha_id String
  - alert_id String
  - vendor String
  - product String
  - normalized String — serialized normalized object
  - error_message String
  - attempts UInt8 DEFAULT 0
  - last_error_at Nullable(DateTime64(3))
  - created_at DateTime64(3) DEFAULT now()
- Engine: MergeTree()
- Partition: toYYYYMM(created_at)
- Order by: (alpha_id, alert_id, created_at)
- Notes: process this table via a DLQ worker to retry or escalate problematic normalization outputs

Recommended indexes & materialized views
- Materialized views to project frequent analytic columns (e.g., counts per severity per day) can reduce query cost
- Use secondary tables or materialized views for Neo4j exports (e.g., nodes/edges extract) to avoid heavy queries at export time

Retention & TTL
- Raw payloads: longer retention (e.g., 90-365 days) as they are useful for investigations. Add TTL to the table if desired.
- Normalized records: retention 365+ days (depends on compliance). Use TTL to drop older data or move to cheaper storage.
- Embeddings: consider retaining vectors for as long as models rely on history — if storing externally, keep only references in ClickHouse

ETL and operational notes
- Ingestion flow (MVP without Kafka):
  1. API stores raw JSON to MinIO (object) and inserts metadata into `alerts_raw`.
  2. Normalization worker polls `ingestionRepo`, normalizes payloads, writes `alerts_normalized` via ClickHouse helper.
  3. On ClickHouse write failure: write a DLQ record to `alerts_normalized_dlq` and schedule retry.
  4. Embedding worker extracts text/fields, generates vector, writes to `alerts_embeddings` or external vector store and saves `embedding_id` in `alerts_normalized`.

- Bulk load: use `INSERT ... FORMAT JSONEachRow` for efficient HTTP-based insert from Node.
- Backfills: export raw payloads from MinIO, normalize in batch, and upsert into `alerts_normalized`.

Where the DDL lives
- `scripts/ddl/01_alerts_raw.sql`
- `scripts/ddl/02_alerts_normalized.sql`
- `scripts/ddl/03_alerts_embeddings.sql`
- `scripts/ddl/04_normalization_dlq.sql`

Example queries
- Select recent high-severity normalized alerts:
  SELECT * FROM security_alerts.alerts_normalized WHERE severity = 'high' ORDER BY timestamp DESC LIMIT 100;

- Find alerts with same file hash:
  SELECT alpha_id, alert_id, timestamp FROM security_alerts.alerts_normalized WHERE file_hash = 'abcd1234' ORDER BY timestamp DESC;

- Get embeddings metadata for alert:
  SELECT * FROM security_alerts.alerts_embeddings WHERE alpha_id = 'alpha-001' AND alert_id = 's1-1001';

If you want I can:
- Add these table schemas as OpenAPI components.schemas so Swagger UI displays them, or
- Add an `/api/admin/ddl` endpoint to serve the SQL files directly.

