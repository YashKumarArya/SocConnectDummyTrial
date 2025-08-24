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
    severity LowCardinality(String) COMMENT 'dot: severity_id',
    category LowCardinality(String),
    event_action LowCardinality(String),

    -- Host (actor.host.*)
    host_id Nullable(String) COMMENT 'dot: host.id',
    host_hostname Nullable(String) COMMENT 'dot: host.hostname',
    host_ip Nullable(String) COMMENT 'dot: host.ip',
    host_os_name Nullable(String) COMMENT 'dot: host.os.name',
    host_os_version Nullable(String) COMMENT 'dot: host.os.version',
    host_group_name Nullable(String) COMMENT 'dot: host.group.name',

    -- User (actor.user.*)
    user_name Nullable(String) COMMENT 'dot: actor.process.user.name',
    user_upn Nullable(String) COMMENT 'dot: actor.user.upn',

    -- Process (actor.process.*)
    process_name Nullable(String) COMMENT 'dot: process.name',
    process_mitigation_status Nullable(String),
    process_initiated_by Nullable(String),
    process_analyst_verdict Nullable(String),

    -- File (actor.process.file.*)
    file_path Nullable(String) COMMENT 'dot: file.path',
    file_sha1 Nullable(String) COMMENT 'dot: sha1',
    file_sha256 Nullable(String) COMMENT 'dot: sha256',
    file_md5 Nullable(String) COMMENT 'dot: md5',
    file_size Nullable(UInt64) COMMENT 'dot: file.size',
    file_extension Nullable(String) COMMENT 'dot: file.extension',
    file_extension_type Nullable(String) COMMENT 'dot: file.extension_type',
    file_publisher Nullable(String) COMMENT 'dot: file.publisher',

    -- Threat fields (threat.*)
    threat_id Nullable(String) COMMENT 'dot: threat.id',
    threat_name Nullable(String) COMMENT 'dot: threat_name',
    threat_classification Nullable(String),
    threat_confidence Nullable(String) COMMENT 'dot: threat.confidence',
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
    source_ip Nullable(String) COMMENT 'dot: source.ip',
    dest_ip Nullable(String) COMMENT 'dot: destination.ip',
    src_username Nullable(String) COMMENT 'dot: actor.process.user.name',
    dest_username Nullable(String),
    url Nullable(String),
    email_from Nullable(String),
    email_to Nullable(String),
    email_subject Nullable(String),

    timestamp DateTime64(3) COMMENT 'dot: event_time',
    normalized JSON,
    embedding_id Nullable(String)
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (alpha_id, alert_id);
