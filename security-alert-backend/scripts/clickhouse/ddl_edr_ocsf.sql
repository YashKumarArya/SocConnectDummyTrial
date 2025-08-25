-- ==========================================================
-- ClickHouse DDL: EDR → OCSF (v4, de-duplicated)
-- ==========================================================

CREATE DATABASE IF NOT EXISTS soc;

CREATE TABLE IF NOT EXISTS soc.edr_alerts_ocsf
(
    -- =========== Identity / ingestion ===========
    alpha_id String DEFAULT '',
    alert_id String DEFAULT ''                                COMMENT 'alert.id',
    event_id String DEFAULT ''                                COMMENT 'id',
    raw_object_key String DEFAULT '',
    source_vendor LowCardinality(String) DEFAULT '',
    source_product LowCardinality(String) DEFAULT '',
    ingested_at DateTime64(3) DEFAULT now(),

    -- =========== Event times ===========
    event_time DateTime DEFAULT now()                         COMMENT 'time',
    identified_at DateTime DEFAULT now()                      COMMENT 'threat.detected_time',

    -- =========== Process / Actor ===========
    originator_process String DEFAULT ''                      COMMENT 'process.name',
    malicious_process_arguments String DEFAULT ''             COMMENT 'process.cmd.args',
    process_user String DEFAULT ''                            COMMENT 'actor.process.user.name',
    process_user_domain String DEFAULT ''                     COMMENT 'actor.process.user.domain',
    actor_user_name String DEFAULT ''                         COMMENT 'actor.user.name',
    is_fileless Bool DEFAULT 0                                COMMENT 'process.isFileless',

    -- =========== File ===========
    file_name String DEFAULT ''                               COMMENT 'file.name',
    file_uid String DEFAULT ''                                COMMENT 'file.uid',
    file_path String DEFAULT ''                               COMMENT 'file.path',
    file_size UInt64 DEFAULT 0                                COMMENT 'file.size',
    file_extension String DEFAULT ''                          COMMENT 'file.extension',
    file_extension_type String DEFAULT ''                     COMMENT 'file.extension_type',
    file_verification_type LowCardinality(String) DEFAULT ''  COMMENT 'file.verification.type',
    file_signature_certificate_status LowCardinality(String) DEFAULT '' COMMENT 'file.signature.certificate.status',
    file_signature_certificate_issuer String DEFAULT ''       COMMENT 'file.signature.certificate.issuer',
    sha1 String DEFAULT ''                                    COMMENT 'file.hashes.sha1',
    sha256 String DEFAULT ''                                  COMMENT 'file.hashes.sha256',
    md5 String DEFAULT ''                                     COMMENT 'file.hashes.md5',
    is_valid_certificate Bool DEFAULT 0                       COMMENT 'file.signature.certificate.is_valid',
    file_reputation_score Int32 DEFAULT 0                     COMMENT 'file.reputation.score',
    file_depth UInt32 DEFAULT 0                               COMMENT 'file.analysis.depth',
    file_entropy Float64 DEFAULT 0                            COMMENT 'file.analysis.entropy',

    -- =========== Detection / Incident / Remediation ===========
    indicators Array(String)                                  COMMENT 'threat.indicators',
    behavioral_indicators Array(String)                       COMMENT 'threat.behavior.observed',
    confidence_level UInt8 DEFAULT 0                          COMMENT 'threat.confidence',
    is_confident Bool DEFAULT 0                               COMMENT 'threat.confidence.is_confident',
    classification LowCardinality(String) DEFAULT ''          COMMENT 'threat.classification',
    analyst_verdict LowCardinality(String) DEFAULT ''         COMMENT 'threat.verdict',
    threat_id String DEFAULT ''                               COMMENT 'threat.id',
    threat_name String DEFAULT ''                             COMMENT 'threat.name',
    detection_type LowCardinality(String) DEFAULT ''          COMMENT 'threat.detection.type',

    mitigation_status LowCardinality(String) DEFAULT ''       COMMENT 'remediation.status',
    remediation_uid String DEFAULT ''                         COMMENT 'remediation.uid',
    remediation_desc String DEFAULT ''                        COMMENT 'remediation.desc',
    remediation_result String DEFAULT ''                      COMMENT 'remediation.result',
    remediation_start_time DateTime DEFAULT now()             COMMENT 'remediation.start_time',
    remediation_end_time DateTime DEFAULT now()               COMMENT 'remediation.end_time',

    incident_status LowCardinality(String) DEFAULT ''         COMMENT 'incident.status',
    incident_desc String DEFAULT ''                           COMMENT 'incident.desc',

    -- Scores / severity
    gnn_score_false_positive Float32 DEFAULT 0                COMMENT 'gnn_score.false_positive',
    ml_score_false_positive Float32 DEFAULT 0                 COMMENT 'ml_score.false_positive',
    rule_base_score_false_positive Float32 DEFAULT 0          COMMENT 'rule_base_score.false_positive',
    severity_id UInt16 DEFAULT 0                              COMMENT 'severity_id',

    -- =========== Device / Agent / Network ===========
    agent_mitigation_mode LowCardinality(String) DEFAULT ''   COMMENT 'device.agents[].state',
    agent_version String DEFAULT ''                           COMMENT 'device.agents[].version',
    agent_is_active Bool DEFAULT 0                            COMMENT 'device.is_active',
    agent_os_type LowCardinality(String) DEFAULT ''           COMMENT 'device.os.type',
    device_os_name LowCardinality(String) DEFAULT ''          COMMENT 'device.os.name',
    device_os_build String DEFAULT ''                         COMMENT 'device.os.build',
    device_type LowCardinality(String) DEFAULT ''             COMMENT 'device.type',
    device_uuid String DEFAULT ''                             COMMENT 'device.uuid',
    device_domain String DEFAULT ''                           COMMENT 'device.domain',
    agent_computer_name String DEFAULT ''                     COMMENT 'device.hostname',
    agent_network_status LowCardinality(String) DEFAULT ''    COMMENT 'device.network.status',
    agent_machine_type LowCardinality(String) DEFAULT ''      COMMENT 'agentMachineType',

    -- IPs / interfaces
    device_ipv4_addresses Array(IPv4) DEFAULT []              COMMENT 'device.ipv4_addresses[]',
    device_interface_names Array(String) DEFAULT []           COMMENT 'device.interface.name',
    device_interface_ips Array(String) DEFAULT []             COMMENT 'device.interface.ip',
    device_interface_macs Array(String) DEFAULT []            COMMENT 'device.interface.mac',

    -- Groups / location
    device_group_names Array(String) DEFAULT []               COMMENT 'device.groups[].name',
    device_group_uids Array(String) DEFAULT []                COMMENT 'device.groups[].uid',
    device_location_desc String DEFAULT ''                    COMMENT 'device.location.desc',
    device_location_uid String DEFAULT ''                     COMMENT 'device.location.uid',

    -- =========== Malware ===========
    malware_names Array(String) DEFAULT []                    COMMENT 'malware[].name[]',
    malware_classification_ids Array(String) DEFAULT []       COMMENT 'malware[].classification_ids[]',

    -- =========== Enrichments (parallel arrays) ===========
    enrichments_data_name Array(String) DEFAULT []            COMMENT 'enrichments[].data.name',
    enrichments_data_type Array(String) DEFAULT []            COMMENT 'enrichments[].data.type',
    enrichments_data_classification Array(String) DEFAULT []  COMMENT 'enrichments[].data.classification',
    enrichments_data_confidence Array(UInt8) DEFAULT []       COMMENT 'enrichments[].data.confidence',
    enrichments_data_risk_score Array(Float32) DEFAULT []     COMMENT 'enrichments[].data.risk_score',
    enrichments_data_severity Array(String) DEFAULT []        COMMENT 'enrichments[].data.severity',
    enrichments_data_size Array(UInt64) DEFAULT []            COMMENT 'enrichments[].data.size',
    enrichments_data_resource Array(String) DEFAULT []        COMMENT 'enrichments[].data.resource',
    enrichments_data_malicious Array(UInt8) DEFAULT []        COMMENT 'enrichments[].data.malicious',
    enrichments_data_suspicious Array(UInt8) DEFAULT []       COMMENT 'enrichments[].data.suspicious',
    enrichments_data_positives Array(UInt32) DEFAULT []       COMMENT 'enrichments[].data.positives',
    enrichments_data_total Array(UInt32) DEFAULT []           COMMENT 'enrichments[].data.total',
    enrichments_data_scan_time Array(DateTime) DEFAULT []     COMMENT 'enrichments[].data.scan_time',
    enrichments_data_first_seen_time Array(DateTime) DEFAULT [] COMMENT 'enrichments[].data.first_seen_time',
    enrichments_data_stats_confirmed_timeout Array(UInt32) DEFAULT [] COMMENT 'enrichments[].data.stats.confirmed_timeout',
    enrichments_data_stats_failure Array(UInt32) DEFAULT []   COMMENT 'enrichments[].data.stats.failure',
    enrichments_data_stats_harmless Array(UInt32) DEFAULT []  COMMENT 'enrichments[].data.stats.harmless',
    enrichments_data_stats_malicious Array(UInt32) DEFAULT [] COMMENT 'enrichments[].data.stats.malicious',
    enrichments_data_stats_suspicious Array(UInt32) DEFAULT [] COMMENT 'enrichments[].data.stats.suspicious',
    enrichments_data_stats_timeout Array(UInt32) DEFAULT []   COMMENT 'enrichments[].data.stats.timeout',
    enrichments_data_stats_undetected Array(UInt32) DEFAULT [] COMMENT 'enrichments[].data.stats.undetected',
    enrichments_data_stats_unsupported Array(UInt32) DEFAULT [] COMMENT 'enrichments[].data.stats.unsupported',

    -- =========== Metadata (product/features) ===========
    metadata_product_feature_name String DEFAULT ''           COMMENT 'metadata.product.feature.name',
    metadata_product_feature_name_keys Array(String) DEFAULT []   COMMENT 'metadata.product.feature.name[].key',
    metadata_product_feature_name_titles Array(String) DEFAULT [] COMMENT 'metadata.product.feature.name[].title',
    metadata_product_feature_version String DEFAULT ''        COMMENT 'metadata.product.feature.version',
    metadata_product_name Array(String) DEFAULT []            COMMENT 'metadata.product.name[]',

    -- Upsert support
    version UInt32 DEFAULT 1
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (alpha_id)
SETTINGS index_granularity = 8192;