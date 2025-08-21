-- DDL: alerts_raw
-- Raw alert payloads (store the original JSON as a string + a few searchable columns)
CREATE DATABASE IF NOT EXISTS security_alerts;

CREATE TABLE IF NOT EXISTS security_alerts.alerts_raw
(
    alpha_id String,
    alert_id String,
    vendor String,
    product String,
    received_at DateTime64(3) DEFAULT now(),

    -- Common extractable fields (optional)
    host_id Nullable(String),
    host_hostname Nullable(String),
    host_ip Nullable(String),
    user_name Nullable(String),
    user_upn Nullable(String),
    process_name Nullable(String),

    -- Threat summary
    threat_id Nullable(String),
    threat_name Nullable(String),

    raw String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(received_at)
ORDER BY (alpha_id, alert_id);
