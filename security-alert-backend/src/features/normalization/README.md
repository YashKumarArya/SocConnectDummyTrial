Normalization feature

Endpoints:
- POST /api/normalization/:id/normalized  -> submit normalized payload or run normalization against provided body
- POST /api/normalization/normalize/trigger/:id -> trigger normalization for raw alert id
- GET /api/normalization/:id -> fetch stored normalized record (MVP in-memory)

Flow:
- Worker polls ingestion repo for unprocessed raw alerts and normalizes them using src/common/normalizer.hybrid.ts
- Normalized records saved to normalization repo (in-memory stub). Replace with ClickHouse later.
