import { Request, Response } from 'express';
import clickhouse from '../../libs/clickhouse/query';

export function flatten(obj: any, out: Record<string, any> = {}, prefix = ''): Record<string, any> {
  if (obj === null || obj === undefined) return out;
  if (typeof obj !== 'object' || obj instanceof Date) {
    out[prefix] = obj;
    return out;
  }
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => {
      const key = prefix ? `${prefix}[${i}]` : `[${i}]`;
      flatten(v, out, key);
    });
    return out;
  }
  Object.entries(obj).forEach(([k, v]) => {
    const key = prefix ? `${prefix}.${k}` : k;
    flatten(v, out, key);
  });
  return out;
}

const DEV_SAMPLE_OCSF = {
  threat: {
    detected_time: '2025-08-21T11:42:05Z',
    id: '2261508184229652674',
    name: 'PUA/WinService',
    confidence: 87,
    classification: 'Security Finding',
    verdict: 'true_positive',
    detection: { type: 'realtime' },
    indicators: ['pua', 'service_install'],
    behavior: { observed: ['persistence_attempt'] }
  },
  process: {
    name: 'svchost.exe',
    cmd: { args: 'svchost.exe -k netsvcs' },
    isFileless: false
  },
  actor: {
    process: { user: { name: 'NT AUTHORITY\\SYSTEM' } },
    user: { name: 'corp\\svc-soc' }
  },
  file: {
    path: 'C:\\Windows\\System32\\svchost.exe',
    size: 1575525,
    extension: 'exe',
    verification: { type: 'sha256RSA' },
    signature: { certificate: { status: 'valid' } },
    hashes: {
      sha1: '356bb3a34e5ef3b3fdb4f1e03e44375befa8a3eb',
      sha256: '9d49eb24851eed0d549b23af2e1912bfb8f3c8fa84c52dd0c41724610abcd123',
      md5: '4bc006c9f27a997212c89955c1f0b8f5'
    },
    analysis: { depth: 3, entropy: 6.72 }
  },
  remediation: { status: 'not_mitigated' },
  incident: { status: 'unresolved' },
  device: {
    os: { type: 'windows' },
    domain: 'CORP',
    hostname: 'WIN-SOC-SRV01',
    ipv4_addresses: ['10.10.10.25'],
    agents: [ { state: 'protect', is_active: true, version: '23.4.1' } ],
    network: { status: 'connected' }
  }
};

// List of columns defined in scripts/clickhouse/ddl_edr_ocsf.sql
const TABLE_COLUMNS = [
  'alpha_id','raw_object_key','source_vendor','source_product','ingested_at','identified_at',
  'originator_process','malicious_process_arguments','process_user','is_fileless',
  'file_path','file_size','file_extension','file_verification_type','file_signature_certificate_status',
  'sha1','sha256','md5','file_depth','file_entropy',
  'indicators','behavioral_indicators','confidence_level','classification','mitigation_status','incident_status','analyst_verdict','threat_id','threat_name','detection_type',
  'agent_os_type','agent_mitigation_mode','agent_network_status','agent_is_active','agent_domain','agent_computer_name','agent_ipv4','agent_version','agent_last_logged_in_user_name','agent_machine_type','version'
];

// Map table columns to OCSF flattened paths
const COLUMN_TO_OCSF_PATH: Record<string, string> = {
  alpha_id: 'meta.alpha_id',
  raw_object_key: 'meta.raw_object_key',
  source_vendor: 'meta.source_vendor',
  source_product: 'meta.source_product',
  ingested_at: 'meta.ingested_at',
  identified_at: 'meta.identified_at',

  originator_process: 'process.name',
  malicious_process_arguments: 'process.cmd.args',
  process_user: 'actor.process.user.name',
  is_fileless: 'process.isFileless',

  file_path: 'file.path',
  file_size: 'file.size',
  file_extension: 'file.extension',
  file_verification_type: 'file.verification.type',
  file_signature_certificate_status: 'file.signature.certificate.status',

  sha1: 'file.hashes.sha1',
  sha256: 'file.hashes.sha256',
  md5: 'file.hashes.md5',

  file_depth: 'file.analysis.depth',
  file_entropy: 'file.analysis.entropy',

  indicators: 'threat.indicators',
  behavioral_indicators: 'threat.behavior.observed',
  confidence_level: 'threat.confidence',
  classification: 'threat.classification',
  mitigation_status: 'remediation.status',
  incident_status: 'incident.status',
  analyst_verdict: 'threat.verdict',
  threat_id: 'threat.id',
  threat_name: 'threat.name',
  detection_type: 'threat.detection.type',

  agent_os_type: 'device.os.type',
  agent_mitigation_mode: 'device.agents[0].state',
  agent_network_status: 'device.network.status',
  agent_is_active: 'device.agents[0].is_active',
  agent_domain: 'device.domain',
  agent_computer_name: 'device.hostname',
  agent_ipv4: 'device.ipv4_addresses[0]',
  agent_version: 'device.agents[0].version',
  agent_last_logged_in_user_name: 'actor.user.name',
  agent_machine_type: 'device.agent_machine_type'
};

function pruneEmpty(obj: any): any {
  if (obj === null || obj === undefined) return undefined;
  if (typeof obj !== 'object' || obj instanceof Date) return obj;
  if (Array.isArray(obj)) {
    const a = obj.map(pruneEmpty).filter((v) => v !== undefined && !(Array.isArray(v) && v.length === 0));
    return a.length === 0 ? undefined : a;
  }
  const out: any = {};
  Object.entries(obj).forEach(([k, v]) => {
    const p = pruneEmpty(v);
    if (p !== undefined && !(typeof p === 'string' && p === '')) out[k] = p;
  });
  return Object.keys(out).length === 0 ? undefined : out;
}

export async function fetchRowsByAlphaId(alphaId: string) {
  const sql = `SELECT * FROM soc.edr_alerts_ocsf WHERE alpha_id = '${alphaId}' FORMAT JSONEachRow`;
  try {
    const rows: any = await clickhouse.querySQL(sql);
    if (!rows || rows.length === 0) return [];
    return rows;
  } catch (err: any) {
    console.error('ClickHouse query failed:', err && err.message ? err.message : err);
    if (process.env.NODE_ENV !== 'production') return [DEV_SAMPLE_OCSF];
    return [];
  }
}

export function mapRowToOCSF(row: any) {
  if (!row) return null;
  const ocsf: any = {
    threat: {
      detected_time: row.identified_at || row.ingested_at || undefined,
      id: row.threat_id || row.alert_id || '',
      name: row.threat_name || '',
      confidence: row.confidence_level ?? undefined,
      classification: row.classification || '',
      verdict: row.analyst_verdict || '',
      detection: { type: row.detection_type || undefined },
      indicators: Array.isArray(row.indicators) ? row.indicators : (row.indicators ? [row.indicators] : []),
      behavior: { observed: Array.isArray(row.behavioral_indicators) ? row.behavioral_indicators : (row.behavioral_indicators ? [row.behavioral_indicators] : []) }
    },
    process: {
      name: row.originator_process || '',
      cmd: { args: row.malicious_process_arguments || '' },
      isFileless: !!row.is_fileless
    },
    actor: {
      process: { user: { name: row.agent_last_logged_in_user_name || '' } },
      user: { name: row.agent_last_logged_in_user_name || '' }
    },
    file: {
      path: row.file_path || '',
      size: row.file_size ?? 0,
      extension: row.file_extension || '',
      verification: { type: row.file_verification_type || '' },
      signature: { certificate: { status: row.file_signature_certificate_status || '' } },
      hashes: {
        sha1: row.sha1 || '',
        sha256: row.sha256 || '',
        md5: row.md5 || ''
      },
      analysis: { depth: row.file_depth ?? undefined, entropy: row.file_entropy ?? undefined }
    },
    remediation: { status: row.mitigation_status || '' },
    incident: { status: row.incident_status || '' },
    device: {
      os: { type: row.agent_os_type || '' },
      domain: row.agent_domain || '',
      hostname: row.agent_computer_name || '',
      ipv4_addresses: row.agent_ipv4 ? (Array.isArray(row.agent_ipv4) ? row.agent_ipv4 : [String(row.agent_ipv4)]) : [],
      agents: [ {
        state: row.agent_mitigation_mode || '',
        is_active: !!row.agent_is_active,
        version: row.agent_version || ''
      } ],
      network: { status: row.agent_network_status || '' }
    },
    meta: {
      ingested_at: row.ingested_at,
      identified_at: row.identified_at,
      source_vendor: row.source_vendor,
      source_product: row.source_product,
      raw_object_key: row.raw_object_key,
      alpha_id: row.alpha_id,
      alert_id: row.alert_id
    }
  };

  // prune empty fields so response only contains values present in the table
  return pruneEmpty(ocsf) || {};
}

export async function getOCSF(req: Request, res: Response) {
  const alphaId = req.params.alphaId;
  if (!alphaId) return res.status(400).json({ error: 'alphaId required' });
  const rows = await fetchRowsByAlphaId(alphaId);
  if (!rows || rows.length === 0) return res.status(404).json({ error: 'OCSF not found' });
  const results = rows.map((r: any) => mapRowToOCSF(r));
  return res.json({ payload: { ocsf: results }, routes_count: results.length });
}

export async function getOCSFFlat(req: Request, res: Response) {
  const alphaId = req.params.alphaId;
  if (!alphaId) return res.status(400).json({ error: 'alphaId required' });
  const rows = await fetchRowsByAlphaId(alphaId);
  if (!rows || rows.length === 0) return res.status(404).json({ error: 'OCSF not found' });

  const allowedPaths = new Set(Object.values(COLUMN_TO_OCSF_PATH));

  const flatList: Record<string, any>[] = rows.map((r: any) => {
    const ocsf = mapRowToOCSF(r);
    const flat = flatten(ocsf);
    const prefixed: Record<string, any> = {};
    // include only allowed OCSF paths in the flat response (keep original key format)
    for (const p of allowedPaths) {
      if (flat[p] !== undefined) prefixed[p] = flat[p];
    }
    return prefixed;
  });

  return res.json({ payload: { ocsf: flatList }, routes_count: flatList.length });
}

export async function getAlertsSourceList(req: Request, res: Response) {
  try {
    const sql = `SELECT threat_id, source_vendor FROM soc.edr_alerts_ocsf LIMIT 100 FORMAT JSONEachRow`;
    const rows: any = await clickhouse.querySQL(sql);
    const list = (rows || []).map((r: any) => ({ alert_id: r.threat_id || '', source: r.source_vendor || '' })).filter((x: any) => x.alert_id || x.source);

    if (!list || list.length === 0) {
      // fallback sample payload
      const sample = [
        { alert_id: 'ALERT-0001', source: 'SentinalOne' },
        { alert_id: 'ALERT-0002', source: 'CrowdStrike' },
        { alert_id: 'ALERT-0003', source: 'Checkpoint' },
        { alert_id: 'ALERT-0004', source: 'PaloAlto' },
        { alert_id: 'ALERT-0005', source: 'Fortinet' },
        { alert_id: 'ALERT-0006', source: 'Proofpoint' }
      ];
      return res.json({ ok: true, data: sample });
    }

    return res.json({ ok: true, data: list });
  } catch (err: any) {
    console.error('failed to query alert sources', err?.message || err);
    return res.status(500).json({ ok: false, error: String(err?.message || err) });
  }
}
