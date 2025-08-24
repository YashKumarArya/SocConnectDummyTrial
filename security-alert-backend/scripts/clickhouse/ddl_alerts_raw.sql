-- DDL: raw alerts table
-- Stores the original raw alert JSON as a string and uses alpha_id as the canonical key

CREATE DATABASE IF NOT EXISTS soc;

CREATE TABLE IF NOT EXISTS soc.alerts_raw (
  alpha_id String,
  alert_id String,
  raw_alert String,
  source_vendor String DEFAULT '',
  source_product String DEFAULT '',
  ingested_at DateTime64(6) DEFAULT now(),
  version UInt64 DEFAULT toUInt64(toUnixTimestamp(now()))
) ENGINE = ReplacingMergeTree(version)
ORDER BY (alpha_id);
