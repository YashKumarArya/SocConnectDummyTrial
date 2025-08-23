CREATE DATABASE IF NOT EXISTS soc;

CREATE TABLE IF NOT EXISTS soc.edr_alerts_ocsf
(
    -- =========== Identity / ingestion ===========
 
    alpha_id String DEFAULT '',
    raw_object_key String DEFAULT '',                    -- object path to raw alert (S3/MinIO/etc.)
    source_vendor LowCardinality(String) DEFAULT '',     -- dataSource.vendor
    source_product LowCardinality(String) DEFAULT '',    -- dataSource.name
    ingested_at DateTime64(3) DEFAULT now(),

    -- =========== Event times ===========
    identified_at DateTime DEFAULT now(),                -- OCSF: threat.detected_time / time

    -- =========== Process Activity ===========
    originator_process String DEFAULT ''                 -- OCSF: process.name
        COMMENT 'process.name',
    malicious_process_arguments String DEFAULT ''        -- OCSF: process.cmd.args
        COMMENT 'process.cmd.args',
    process_user String DEFAULT ''                       -- OCSF: actor.process.user.name
        COMMENT 'actor.process.user.name',
    is_fileless Bool DEFAULT 0                           -- OCSF: process.isFileless
        COMMENT 'process.isFileless',

    -- =========== File Activity ===========
    file_path String DEFAULT ''                          -- OCSF: file.path
        COMMENT 'file.path',
    file_size UInt64 DEFAULT 0                           -- OCSF: file.size
        COMMENT 'file.size',
    file_extension String DEFAULT ''                     -- OCSF: file.extension (from fileExtensionType)
        COMMENT 'file.extension',
    file_verification_type LowCardinality(String) DEFAULT ''   -- OCSF: file.verification.type
        COMMENT 'file.verification.type',
    file_signature_certificate_status LowCardinality(String) DEFAULT ''  -- OCSF: file.signature.certificate.status (valid/expired/unknown)
        COMMENT 'file.signature.certificate.status',

    sha1 String DEFAULT ''                      -- OCSF: file.hashes.sha1
        COMMENT 'file.hashes.sha1',
    sha256 String DEFAULT ''                    -- OCSF: file.hashes.sha256
        COMMENT 'file.hashes.sha256',
    md5 String DEFAULT ''                       -- OCSF: file.hashes.md5
        COMMENT 'file.hashes.md5',

    -- Optional analytics per your note
    file_depth UInt32 DEFAULT 0                          -- custom analytic
        COMMENT 'custom: file.depth',
    file_entropy Float64 DEFAULT 0                       -- custom analytic
        COMMENT 'custom: file.entropy',

    -- =========== Detection / Incident Finding ===========
    indicators Array(String)                             -- OCSF: threat.indicators
        COMMENT 'threat.indicators',
    behavioral_indicators Array(String)                  -- OCSF: threat.behavior.observed
        COMMENT 'threat.behavior.observed',
    confidence_level UInt8 DEFAULT 0                     -- OCSF: threat.confidence (0-100)
        COMMENT 'threat.confidence',
    classification LowCardinality(String) DEFAULT ''     -- OCSF: threat.classification
        COMMENT 'threat.classification',
    mitigation_status LowCardinality(String) DEFAULT ''  -- OCSF: remediation.status
        COMMENT 'remediation.status',
    incident_status LowCardinality(String) DEFAULT ''    -- OCSF: incident.status
        COMMENT 'incident.status',
    analyst_verdict LowCardinality(String) DEFAULT ''    -- OCSF: threat.verdict
        COMMENT 'threat.verdict',
    threat_id String DEFAULT ''                          -- OCSF: threat.id
        COMMENT 'threat.id',
    threat_name String DEFAULT ''                        -- OCSF: threat.name (malware/family)
        COMMENT 'threat.name',
    detection_type LowCardinality(String) DEFAULT ''     -- OCSF: threat.detection.type
        COMMENT 'threat.detection.type',

    -- =========== Device / Agent / Network ===========
    agent_os_type LowCardinality(String) DEFAULT ''      -- OCSF: device.os.type
        COMMENT 'device.os.type',
    agent_mitigation_mode LowCardinality(String) DEFAULT '' -- OCSF: device.agents[].state (map at read time)
        COMMENT 'device.agents[].state',
    agent_network_status LowCardinality(String) DEFAULT ''   -- OCSF: device.network.status
        COMMENT 'device.network.status',
    agent_is_active Bool DEFAULT 0                       -- OCSF: device.is_active or device.agents[].is_active
        COMMENT 'device.is_active',
    agent_domain String DEFAULT ''                       -- OCSF: device.domain
        COMMENT 'device.domain',
    agent_computer_name String DEFAULT ''                -- OCSF: device.hostname
        COMMENT 'device.hostname',
    agent_ipv4 IPv4 DEFAULT '0.0.0.0'                    -- OCSF: device.ipv4_addresses (expand to array at read time)
        COMMENT 'device.ipv4_addresses',
    agent_version String DEFAULT ''                      -- OCSF: device.agents[].version
        COMMENT 'device.agents[].version',
    agent_last_logged_in_user_name String DEFAULT ''     -- OCSF: actor.user.name
        COMMENT 'actor.user.name',
    agent_machine_type LowCardinality(String) DEFAULT '' -- OCSF: agentMachineType (custom/extension)
        COMMENT 'agentMachineType',

    -- =========== Full OCSF event (normalized JSON) ===========
    -- ocsf String,                                         -- we will not use this as we are storing the ocsf data into the above attributes .store the original normalized OCSF JSON (use JSON type if available) 


    -- =========== Upsert support / housekeeping ===========
    version UInt32 DEFAULT 1
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (alpha_id)
SETTINGS index_granularity = 8192;

-- (Optional) View exposing a concise analytics subset
CREATE VIEW IF NOT EXISTS soc.edr_alerts_summary AS
SELECT
    ingested_at,
    identified_at,
    source_vendor,
    source_product,
    classification,
    mitigation_status,
    incident_status,
    confidence_level,
    analyst_verdict,
    threat_name,
    agent_os_type,
    agent_network_status,
    agent_is_active
FROM soc.edr_alerts_ocsf;