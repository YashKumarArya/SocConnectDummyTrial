import { v4 as uuidv4 } from 'uuid';
import { generateAlphaId } from '../alpha_id';
import config from './index';

async function getFetch() {
  if (typeof fetch !== 'undefined') return (globalThis as any).fetch.bind(globalThis);
  // dynamic import to keep optional
  const nf: any = await import('node-fetch');
  return (nf && (nf.default || nf)) as any;
}

function toISO(d?: string | number | Date) {
  if (!d) return new Date().toISOString();
  const dt = new Date(d);
  if (isNaN(dt.getTime())) return new Date().toISOString();
  return dt.toISOString();
}

export async function insertEDR(alert: any) {
  if (!alert) return false;
  const fetchFn = await getFetch();

  // Use alpha_id as the canonical key. Do NOT fallback to alert.id (we don't want alert id to be the primary key).
  // If alpha_id is missing, generate one (stable uuid) so every row has a key.
  const alphaId = generateAlphaId(alert);

  const row: any = {
    // removed alert_id -- DDL does not have an alert_id column; alpha_id is the key
    alpha_id: alphaId,
    raw_object_key: alert.raw_object_key || alert.rawObjectKey || '',
    source_vendor: alert.source_vendor || alert.vendor || '',
    source_product: alert.source_product || alert.product || '',
    ingested_at: toISO(alert.ingested_at || alert.ingestedAt || new Date()),
    identified_at: toISO(alert.identified_at || alert.identifiedAt || alert?.threat?.detected_time || undefined),

    originator_process: alert?.process?.name || alert?.originator_process || '',
    malicious_process_arguments: alert?.process?.cmd?.args || alert?.malicious_process_arguments || '',
    process_user: alert?.actor?.process?.user?.name || alert?.process_user || '',
    is_fileless: alert?.process?.isFileless || alert?.is_fileless || 0,

    file_path: alert?.file?.path || alert?.file_path || '',
    file_size: alert?.file?.size || alert?.file_size || 0,
    file_extension: alert?.file?.extension || alert?.file_extension || '',
    file_verification_type: alert?.file?.verification?.type || alert?.file_verification_type || '',
    file_signature_certificate_status: alert?.file?.signature?.certificate?.status || alert?.file_signature_certificate_status || '',

    sha1: alert?.file?.hashes?.sha1 || alert?.sha1 || '',
    sha256: alert?.file?.hashes?.sha256 || alert?.sha256 || '',
    md5: alert?.file?.hashes?.md5 || alert?.md5 || '',

    indicators: Array.isArray(alert?.threat?.indicators) ? alert.threat.indicators : (alert?.indicators ? [alert.indicators] : []),
    behavioral_indicators: Array.isArray(alert?.threat?.behavior?.observed) ? alert.threat.behavior.observed : (alert?.behavioral_indicators ? alert.behavioral_indicators : []),
    confidence_level: alert?.threat?.confidence || alert?.confidence_level || 0,
    classification: alert?.threat?.classification || alert?.classification || '',
    mitigation_status: alert?.remediation?.status || alert?.mitigation_status || '',
    incident_status: alert?.incident?.status || alert?.incident_status || '',
    analyst_verdict: alert?.threat?.verdict || alert?.analyst_verdict || '',
    threat_id: alert?.threat?.id || alert?.threat_id || '',
    threat_name: alert?.threat?.name || alert?.threat_name || '',
    detection_type: alert?.threat?.detection?.type || alert?.detection_type || '',

    agent_os_type: alert?.device?.os?.type || alert?.agent_os_type || '',
    agent_mitigation_mode: alert?.device?.agents?.[0]?.state || alert?.agent_mitigation_mode || '',
    agent_network_status: alert?.device?.network?.status || alert?.agent_network_status || '',
    agent_is_active: alert?.device?.agents?.[0]?.is_active ?? alert?.agent_is_active ?? 0,
    agent_domain: alert?.device?.domain || alert?.agent_domain || '',
    agent_computer_name: alert?.device?.hostname || alert?.agent_computer_name || '',
    agent_ipv4: (Array.isArray(alert?.device?.ipv4_addresses) ? alert.device.ipv4_addresses[0] : alert?.device?.ipv4_addresses) || alert?.agent_ipv4 || '0.0.0.0',
    agent_version: alert?.device?.agents?.[0]?.version || alert?.agent_version || '',
    agent_last_logged_in_user_name: alert?.actor?.user?.name || alert?.agent_last_logged_in_user_name || '',
    agent_machine_type: alert?.agentMachineType || alert?.agent_machine_type || '' ,

    // set version to epoch seconds of ingested_at so ReplacingMergeTree chooses latest by alpha_id
    version: Math.floor(new Date((alert.ingested_at || alert.ingestedAt || new Date())).getTime() / 1000)
  };

  // Build JSONEachRow payload (single row)
  const body = `INSERT INTO soc.edr_alerts_ocsf FORMAT JSONEachRow\n${JSON.stringify(row)}`;

  const res = await fetchFn(config.url, {
    method: 'POST',
    headers: (() => {
      const h: any = { 'Content-Type': 'text/plain' };
      if ((config as any).user && (config as any).password) {
        const token = Buffer.from(`${(config as any).user}:${(config as any).password}`).toString('base64');
        h.Authorization = `Basic ${token}`;
      }
      return h;
    })(),
    body
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`ClickHouse insert failed ${res.status}: ${text}`);
  }

  return true;
}

export default { insertEDR };
