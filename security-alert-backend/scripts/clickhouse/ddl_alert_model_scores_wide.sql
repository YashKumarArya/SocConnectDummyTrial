CREATE TABLE IF NOT EXISTS soc.alert_model_scores_wide
(
    alert_id String                               COMMENT 'id',
    alpha_id String                               COMMENT 'alpha_id',
    ts DateTime DEFAULT now()                     COMMENT 'ts',

    -- GNN
    gnn_confidence Float32                        COMMENT 'supervisor.metadata.agent_results[? agent="GNN"].confidence',
    gnn_verdict LowCardinality(String)            COMMENT 'supervisor.metadata.agent_results[? agent="GNN"].verdict',
    gnn_meta String DEFAULT ''                     COMMENT 'supervisor.metadata.agent_results[? agent="GNN"]',

    -- Rule-based (from triage response)
    rule_confidence Float32                       COMMENT 'triage.prediction.confidence',
    rule_verdict LowCardinality(String)           COMMENT 'triage.prediction.predicted_verdict',
    rule_meta String DEFAULT ''                    COMMENT 'triage.metadata',

    -- EDR (from supervisor agent_results)
    edr_score Float32                             COMMENT 'supervisor.metadata.agent_results[? agent="EDR"].score',
    edr_verdict LowCardinality(String)            COMMENT 'supervisor.metadata.agent_results[? agent="EDR"].verdict',
    edr_meta String DEFAULT ''                     COMMENT 'supervisor.metadata.agent_results[? agent="EDR"]',

    -- Supervisor (overall analysis)
    supervisor_score Float32                       COMMENT 'supervisor.metadata.supervisor_analysis.consolidated_score',
    supervisor_verdict LowCardinality(String)      COMMENT 'supervisor.metadata.supervisor_analysis.final_decision',
    supervisor_meta String DEFAULT ''               COMMENT 'supervisor.metadata',

    -- Summary
    summary String DEFAULT ''                       COMMENT 'summary'
)
ENGINE = SharedMergeTree('/clickhouse/tables/{uuid}/{shard}', '{replica}')
PARTITION BY toYYYYMM(ts)
ORDER BY (alert_id, alpha_id)
SETTINGS index_granularity = 8192;
