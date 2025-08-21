Project TODO
==========

1) FAISS / Similarity
- Provide conda instructions in README for faiss-cpu installation (Miniforge recommended on macOS Apple Silicon).
- Provide Dockerfile + docker-compose for similarity service (FAISS or HNSW service) and ClickHouse for reproducible dev environment.
- Add Node proxy client to hit similarity service endpoints (/build-index, /search, /add-embedding).
- Add example curl commands and a small seed script to create embeddings in ClickHouse and call /build-index.
- Add an alternative implementation using hnswlib (already added) and document install steps.

2) Observatory & Runtime
- Ensure CLICKHOUSE_URL and MinIO env vars are documented and exposed in docker-compose.
- Add health checks for FAISS/HNSW service and ClickHouse to the Node startup.
- Add metrics (Prometheus) for embedding ingestion / DLQ / index build durations.

3) ClickHouse & Database work (next focus)
- Apply DDL in scripts/ddl/ to a running ClickHouse instance (docker-compose or local).
- Run seed loader: scripts/seed/seed_clickhouse_loader.js to populate sample data.
- Review table engines / partitions / TTLs and add suggested optimizations:
  - Partition alerts_normalized by toYYYYMM(timestamp)
  - Use ORDER BY (alpha_id, alert_id, timestamp) or (alpha_id, timestamp)
  - TTL for alerts_raw to expire raw payloads after configurable retention (e.g., 90 days)
  - Create materialized views for pre-aggregated triage stats
- Add ClickHouse backups and index persistence instructions.

4) Embeddings & Indexing
- Decide index strategy for production: HNSW (fast recall, medium RAM) vs IVF+PQ (low RAM, approximate).
- Provide scripts to export embeddings from ClickHouse and build index batch-wise.
- Implement triage endpoint integration to call similarity service and merge scores.

5) Next implementation choices (ask user)
- Add docker-compose for ClickHouse + Node + HNSW service
- Implement Node proxy client for similarity endpoints
- Harden ClickHouse schema (partitioning / TTL / materialized views)

---

Notes:
- I added this TODO to the repository root. Tell me which item to pick next and I will implement it.
