-- Create table to store model scores and verdicts in a wide format
-- Includes metadata JSON in `meta` for bookkeeping

CREATE TABLE IF NOT EXISTS soc.alert_model_scores_wide
(
    alert_id        String,
    alpha_id        String,
    ts              DateTime DEFAULT now(),

    gnn_score       Float32,
    gnn_confidence  Float32,
    gnn_verdict     LowCardinality(String),

    ml_score        Float32,
    ml_confidence   Float32,
    ml_verdict      LowCardinality(String),

    rule_score      Float32,
    rule_confidence Float32,
    rule_verdict    LowCardinality(String),

    meta String DEFAULT '' -- e.g. {"v4_fields_present":49,"v4_fields_total":101,"v4_schema_version":"v4"}
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (alert_id, alpha_id);
