-- DDL: alerts_normalized_dlq
-- Dead-letter queue for normalized rows that failed to persist to the main table
CREATE DATABASE IF NOT EXISTS security_alerts;

CREATE TABLE IF NOT EXISTS security_alerts.alerts_normalized_dlq
(
    alpha_id String,
    alert_id String,
    vendor String,
    product String,
    normalized String,
    error_message String,
    attempts UInt8 DEFAULT 0,
    last_error_at Nullable(DateTime64(3)),
    created_at DateTime64(3) DEFAULT now()
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (alpha_id, alert_id, created_at);
