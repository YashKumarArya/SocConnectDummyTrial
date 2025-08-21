-- DDL: alerts_embeddings
-- Store vector embeddings metadata and an optional reference to an external vector store
CREATE DATABASE IF NOT EXISTS security_alerts;

CREATE TABLE IF NOT EXISTS security_alerts.alerts_embeddings
(
    alpha_id String,
    alert_id String,
    embedding_id String,
    vector Array(Float32),
    dimension UInt32,
    created_at DateTime64(3) DEFAULT now(),

    -- optional references
    file_sha256 Nullable(String),
    host_id Nullable(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (alpha_id, alert_id, embedding_id);
