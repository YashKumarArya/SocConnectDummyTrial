// ---- dotted-only mapping utilities ----

// Flatten nested objects to dotted (supports arrays via [idx])
export function flatten(obj: any, prefix = '', out: Record<string, any> = {}): Record<string, any> {
  if (obj == null) return out;
  const isObj = (x: any) => x && typeof x === 'object' && !Array.isArray(x) && !(x instanceof Date);
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => flatten(v, `${prefix}[${i}]`, out));
    return out;
  }
  if (isObj(obj)) {
    for (const [k, v] of Object.entries(obj)) {
      const p = prefix ? `${prefix}.${k}` : k;
      if (isObj(v) || Array.isArray(v)) flatten(v, p, out);
      else out[p] = v;
    }
    return out;
  }
  out[prefix] = obj;
  return out;
}

export function isAlreadyDotted(x: any) {
  return x && typeof x === 'object' && Object.keys(x).some(k => k.includes('.') || k.includes('['));
}

export function setIfMissing(flat: Record<string, any>, key: string, val: any) {
  if (val === undefined || val === null) return;
  if (!(key in flat) || flat[key] === '' || flat[key] === null || flat[key] === undefined) {
    flat[key] = val;
  }
}

/**
 * Convert raw + optional snake_case sources into a single dotted map.
 * - Keeps existing dotted keys from `raw` as-is.
 * - Adds dotted equivalents from snake_case if missing.
 * - Converts enrichments_* parallel arrays -> enrichments[<idx>].data.*
 * - Builds metadata.product.feature.name as array of {title,key} when keys/titles arrays exist.
 *
 * @param raw       uploaded JSON; may already be dotted or nested
 * @param snake     optional snake_case source (e.g., DB/normalized fields)
 * @param opts      { enrichIndexBase: 1 | 0 } default 1 to match your sample
 */
export function toDottedAlert(
  raw: any,
  snake?: any,
  opts: { enrichIndexBase?: 0 | 1 } = {}
): Record<string, any> {
  const indexBase = opts.enrichIndexBase ?? 1;

  // Start with dotted form of raw (or keep as-is if already dotted)
  const base: Record<string, any> = isAlreadyDotted(raw) ? { ...raw } : flatten(raw || {});
  const s = snake || {};

  // ---- basic identity / scalars (fill only if missing) ----
  setIfMissing(base, 'id', s.id ?? s.alert_id ?? s.alpha_id);
  setIfMissing(base, 'alert_id', s.alert_id);
  setIfMissing(base, 'alpha_id', s.alpha_id);
  setIfMissing(base, 'severity_id', s.severity_id);

  // ---- file.* ----
  setIfMissing(base, 'file.name', s.file_name);
  setIfMissing(base, 'file.uid', s.file_uid);
  setIfMissing(base, 'file.path', s.file_path);
  setIfMissing(base, 'file.size', s.file_size);
  setIfMissing(base, 'file.extension', s.file_extension);
  setIfMissing(base, 'file.extension_type', s.file_extension_type);
  setIfMissing(base, 'file.verification.type', s.file_verification_type);
  setIfMissing(base, 'file.signature.certificate.status', s.file_signature_certificate_status);
  setIfMissing(base, 'file.signature.certificate.issuer', s.file_signature_certificate_issuer);
  setIfMissing(base, 'file.hashes.sha1', s.sha1);
  setIfMissing(base, 'file.hashes.sha256', s.sha256);
  setIfMissing(base, 'file.hashes.md5', s.md5);
  setIfMissing(base, 'file.signature.certificate.is_valid', s.is_valid_certificate);

  // ---- process / actor ----
  setIfMissing(base, 'process.name', s.originator_process);
  setIfMissing(base, 'process.cmd.args', s.malicious_process_arguments);
  setIfMissing(base, 'actor.process.user.name', s.process_user);
  setIfMissing(base, 'actor.process.user.domain', s.process_user_domain);
  setIfMissing(base, 'actor.user.name', s.actor_user_name);
  setIfMissing(base, 'process.isFileless', s.is_fileless);

  // ---- threat.* / incident.* / remediation.* ----
  setIfMissing(base, 'threat.confidence', s.confidence_level);     // keep raw value; do NOT coerce to UInt8 here
  setIfMissing(base, 'threat.classification', s.classification);
  setIfMissing(base, 'threat.verdict', s.analyst_verdict);
  setIfMissing(base, 'threat.id', s.threat_id);
  setIfMissing(base, 'threat.name', s.threat_name);
  setIfMissing(base, 'threat.detection.type', s.detection_type);
  setIfMissing(base, 'incident.status', s.incident_status);
  setIfMissing(base, 'incident.desc', s.incident_desc);
  setIfMissing(base, 'remediation.status', s.mitigation_status);
  setIfMissing(base, 'remediation.uid', s.remediation_uid);
  setIfMissing(base, 'remediation.desc', s.remediation_desc);
  setIfMissing(base, 'remediation.result', s.remediation_result);
  setIfMissing(base, 'remediation.start_time', s.remediation_start_time);
  setIfMissing(base, 'remediation.end_time', s.remediation_end_time);

  // ---- device.* / agent.* ----
  setIfMissing(base, 'device.type', s.device_type);
  setIfMissing(base, 'device.uuid', s.device_uuid);
  setIfMissing(base, 'device.domain', s.device_domain);
  setIfMissing(base, 'device.hostname', s.agent_computer_name);
  setIfMissing(base, 'device.network.status', s.agent_network_status);
  setIfMissing(base, 'device.os.type', s.agent_os_type);
  setIfMissing(base, 'device.os.name', s.device_os_name);
  setIfMissing(base, 'device.os.build', s.device_os_build);
  setIfMissing(base, 'device.is_active', s.agent_is_active);
  setIfMissing(base, 'agentMachineType', s.agent_machine_type);
  // If you hold agent state/version in snake:
  setIfMissing(base, 'device.agents[0].state', s.agent_mitigation_mode);
  setIfMissing(base, 'device.agents[0].version', s.agent_version);

  // ---- metadata.product.feature.* ----
  const kArr: string[] = Array.isArray(s.metadata_product_feature_name_keys) ? s.metadata_product_feature_name_keys : [];
  const tArr: string[] = Array.isArray(s.metadata_product_feature_name_titles) ? s.metadata_product_feature_name_titles : [];
  if (kArr.length || tArr.length) {
    base['metadata.product.feature.name'] = kArr.map((key, i) => ({ key, title: tArr[i] ?? '' }));
  } else if (s.metadata_product_feature_name && base['metadata.product.feature.name'] === undefined) {
    // fallback: simple string if you only have a single name
    base['metadata.product.feature.name'] = s.metadata_product_feature_name;
  }
  setIfMissing(base, 'metadata.product.feature.version', s.metadata_product_feature_version);
  if (Array.isArray(s.metadata_product_name) && base['metadata.product.name'] === undefined) {
    base['metadata.product.name'] = s.metadata_product_name;
  }

  // ---- enrichments: arrays -> dotted enrichments[<idx>].data.* ----
  const E = {
    positives: s.enrichments_data_positives,
    total: s.enrichments_data_total,
    malicious: s.enrichments_data_malicious,
    suspicious: s.enrichments_data_suspicious,
    'stats.malicious': s.enrichments_data_stats_malicious,
    'stats.suspicious': s.enrichments_data_stats_suspicious,
    'stats.undetected': s.enrichments_data_stats_undetected,
    'stats.harmless': s.enrichments_data_stats_harmless,
    'stats.unsupported': s.enrichments_data_stats_unsupported,
    'stats.timeout': s.enrichments_data_stats_timeout,
    // hyphenated variant to match your sample
    'stats.confirmed-timeout': s.enrichments_data_stats_confirmed_timeout,
    'stats.failure': s.enrichments_data_stats_failure,
    'scan_time': s.enrichments_data_scan_time,
  } as Record<string, any[]>;

  const maxLen = Math.max(
    ...Object.values(E).map(a => (Array.isArray(a) ? a.length : 0)),
    0
  );

  for (let i = 0; i < maxLen; i++) {
    for (const [suffix, arr] of Object.entries(E)) {
      if (!Array.isArray(arr)) continue;
      const v = arr[i];
      if (v === undefined) continue;
      const idx = i + indexBase; // 1-based to mirror your example
      const key = suffix === 'scan_time'
        ? `enrichments[${idx}].data.scan_time`
        : `enrichments[${idx}].data.${suffix}`;
      setIfMissing(base, key, v);
    }
  }

  return base;
}
