-- ClickHouse DDL for EDR -> OCSF mapped schema
-- Database: soc
-- Table: edr_alerts_ocsf

CREATE DATABASE IF NOT EXISTS soc;

CREATE TABLE IF NOT EXISTS soc.edr_alerts_ocsf
(
    alert_id UUID,
    alpha_id String DEFAULT '',
    raw_object_key String DEFAULT '',
    source_vendor LowCardinality(String) DEFAULT '',
    source_product LowCardinality(String) DEFAULT '',
    ingested_at DateTime64(3) DEFAULT now(),

    identified_at DateTime DEFAULT now(),

    process_name String DEFAULT '',
    process_file_name String DEFAULT '',
    process_cmd_line String DEFAULT '',
    process_user_name String DEFAULT '',
    is_fileless UInt8 DEFAULT 0,

    file_path String DEFAULT '',
    file_size UInt64 DEFAULT 0,
    file_type String DEFAULT '',
    file_signature_algorithm String DEFAULT '',
    file_signature_certificate_valid UInt8 DEFAULT 0,
    sha1 FixedString(40) DEFAULT '',
    sha256 FixedString(64) DEFAULT '',
    md5 FixedString(32) DEFAULT '',

    finding_types Array(String),
    finding_confidence UInt8 DEFAULT 0,
    finding_class_name LowCardinality(String) DEFAULT '',
    finding_remediation_desc String DEFAULT '',
    finding_state LowCardinality(String) DEFAULT '',
    finding_uid String DEFAULT '',
    finding_verdict LowCardinality(String) DEFAULT '',

    threat_name String DEFAULT '',

    device_os_name LowCardinality(String) DEFAULT '',
    device_os_type LowCardinality(String) DEFAULT '',
    agent_mitigation_mode LowCardinality(String) DEFAULT '',
    agent_network_status LowCardinality(String) DEFAULT '',
    agent_is_active UInt8 DEFAULT 0,

    observables Array(String),

    ocsf String,

    version UInt32 DEFAULT 1
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (ingested_at, alert_id)
SETTINGS index_granularity = 8192;

CREATE VIEW IF NOT EXISTS soc.edr_alerts_summary AS
SELECT
    ingested_at,
    identified_at,
    source_vendor,
    source_product,
    finding_class_name,
    finding_state,
    finding_confidence,
    threat_name,
    device_os_name,
    agent_network_status,
    agent_is_active
FROM soc.edr_alerts_ocsf;
