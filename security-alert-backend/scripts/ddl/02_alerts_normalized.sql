-- DDL: alerts_normalized
-- Normalized alert records for analytics, triage, and exports
CREATE DATABASE IF NOT EXISTS security_alerts;

CREATE TABLE IF NOT EXISTS security_alerts.alerts_normalized
(
    alpha_id String,
    alert_id String,
    vendor String,
    product String,

    -- severity / categorization
    severity LowCardinality(String),
    category LowCardinality(String),
    event_action LowCardinality(String),

    -- Host (actor.host.*)
    host_id Nullable(String),
    host_hostname Nullable(String),
    host_ip Nullable(String),
    host_os_name Nullable(String),
    host_os_version Nullable(String),
    host_group_name Nullable(String),

    -- User (actor.user.*)
    user_name Nullable(String),
    user_upn Nullable(String),

    -- Process (actor.process.*)
    process_name Nullable(String),
    process_mitigation_status Nullable(String),
    process_initiated_by Nullable(String),
    process_analyst_verdict Nullable(String),

    -- File (actor.process.file.*)
    file_path Nullable(String),
    file_sha1 Nullable(String),
    file_sha256 Nullable(String),
    file_md5 Nullable(String),
    file_size Nullable(UInt64),
    file_extension Nullable(String),
    file_extension_type Nullable(String),
    file_publisher Nullable(String),

    -- Threat fields (threat.*)
    threat_id Nullable(String),
    threat_name Nullable(String),
    threat_classification Nullable(String),
    threat_confidence Nullable(String),
    incident_status Nullable(String),
    threat_mitigation_status Nullable(String),
    threat_storyline Nullable(String),

    -- Network interfaces (store as JSON string for arrays)
    host_network_interfaces Nullable(String),

    -- Account
    account_id Nullable(String),
    account_name Nullable(String),
    account_site_id Nullable(String),
    account_site_name Nullable(String),

    -- Certificate (related to file/process signer)
    certificate_id Nullable(String),
    certificate_is_valid Nullable(UInt8),
    certificate_publisher Nullable(String),

    -- Common fields
    source_ip Nullable(String),
    dest_ip Nullable(String),
    src_username Nullable(String),
    dest_username Nullable(String),
    url Nullable(String),
    email_from Nullable(String),
    email_to Nullable(String),
    email_subject Nullable(String),

    timestamp DateTime64(3),
    normalized JSON,
    embedding_id Nullable(String)
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (alpha_id, alert_id);
