import { Request, Response } from 'express';
import { normalizationService } from './normalization.service';
import { ingestionRepo } from '../ingestion/ingestion.repo';
import { insertEDR } from '../../libs/clickhouse/insert_edr';
import { sendNormalizedWebhook } from '../../libs/webhook';

function mapToEDRPayload(orig: any, id: string, providedAlpha?: string) {
  const o = orig || {};
  const alpha = providedAlpha || o.alpha_id || o.alphaId || id;
  const ingested = o.ingested_at || o.ingestedAt || new Date().toISOString();

  return {
    alpha_id: alpha,
    raw_object_key: o.raw_object_key || o.rawObjectKey || o.raw || '',
    source_vendor: o.source_vendor || o.vendor || o.source?.vendor || '',
    source_product: o.source_product || o.product || o.source?.product || '',
    ingested_at: ingested,
    identified_at: o.identified_at || o.identifiedAt || o.threat?.detected_time || undefined,

    originator_process: o.process?.name || o.originator_process || '',
    malicious_process_arguments: o.process?.cmd?.args || o.malicious_process_arguments || '',
    process_user: o.actor?.process?.user?.name || o.process_user || '',
    is_fileless: o.process?.isFileless ?? o.is_fileless ?? 0,

    file_path: o.file?.path || o.file_path || '',
    file_size: o.file?.size || o.file_size || 0,
    file_extension: o.file?.extension || o.file_extension || '',
    file_verification_type: o.file?.verification?.type || o.file_verification_type || '',
    file_signature_certificate_status: o.file?.signature?.certificate?.status || o.file_signature_certificate_status || '',

    sha1: o.file?.hashes?.sha1 || o.sha1 || '',
    sha256: o.file?.hashes?.sha256 || o.sha256 || '',
    md5: o.file?.hashes?.md5 || o.md5 || '',

    indicators: Array.isArray(o.threat?.indicators) ? o.threat.indicators : (o.indicators ? [o.indicators] : []),
    behavioral_indicators: Array.isArray(o.threat?.behavior?.observed) ? o.threat.behavior.observed : (o.behavioral_indicators ? o.behavioral_indicators : []),
    confidence_level: o.threat?.confidence ?? o.confidence_level ?? 0,
    classification: o.threat?.classification || o.classification || '',
    mitigation_status: o.remediation?.status || o.mitigation_status || '',
    incident_status: o.incident?.status || o.incident_status || '',
    analyst_verdict: o.threat?.verdict || o.analyst_verdict || '',
    threat_id: o.threat?.id || o.threat_id || '',
    threat_name: o.threat?.name || o.threat_name || '',
    detection_type: o.threat?.detection?.type || o.detection_type || '',

    agent_os_type: o.device?.os?.type || o.agent_os_type || '',
    agent_mitigation_mode: o.device?.agents?.[0]?.state || o.agent_mitigation_mode || '',
    agent_network_status: o.device?.network?.status || o.agent_network_status || '',
    agent_is_active: o.device?.agents?.[0]?.is_active ?? o.agent_is_active ?? 0,
    agent_domain: o.device?.domain || o.agent_domain || '',
    agent_computer_name: o.device?.hostname || o.agent_computer_name || '',
    agent_ipv4: Array.isArray(o.device?.ipv4_addresses) ? o.device.ipv4_addresses[0] : o.device?.ipv4_addresses || o.agent_ipv4 || '0.0.0.0',
    agent_version: o.device?.agents?.[0]?.version || o.agent_version || '',
    agent_last_logged_in_user_name: o.actor?.user?.name || o.agent_last_logged_in_user_name || '',
    agent_machine_type: o.agentMachineType || o.agent_machine_type || '',

    // if caller supplied numeric version keep it, otherwise derive from ingested_at
    version: typeof o.version === 'number' ? o.version : Math.floor(new Date(ingested).getTime() / 1000)
  };
}

export async function postNormalized(req: Request, res: Response) {
  const id = req.params.id;
  const body = req.body;
  if (!id) return res.status(400).json({ error: 'missing id' });

  // allow direct POST of normalized payload
  const result = await normalizationService.normalize(id, body, req.query.source as string | undefined);

  // If caller provided an alpha_id (in body or query) attempt to persist to EDR table
  const providedAlpha = body?.alpha_id || body?.alphaId || (req.query.alpha_id as string) || (req.query.alphaId as string);
  if (providedAlpha) {
    const orig = (body && typeof body === 'object') ? body : (result && (result as any).original ? (result as any).original : result);
    const edrPayload = mapToEDRPayload(orig, id, providedAlpha);
    try {
      await insertEDR(edrPayload);
    } catch (e: any) {
      console.error('insertEDR failed for alpha_id', providedAlpha, e?.message || e);
      // do not fail the normalization API; caller can retry or inspect logs
    }

    // best-effort: notify external system of normalized payload
    try { await sendNormalizedWebhook({ id, alpha_id: providedAlpha, normalized: result }); } catch (e) { /* swallow */ }
  }

  res.json({ ok: true, id, result });
}

export async function triggerNormalize(req: Request, res: Response) {
  const id = req.params.id;
  if (!id) return res.status(400).json({ error: 'missing id' });

  // get raw from ingestion store and normalize
  const raw = await ingestionRepo.get(id);
  if (!raw) return res.status(404).json({ error: 'raw not found' });

  const result = await normalizationService.normalize(id, raw, req.query.source as string | undefined);
  res.status(202).json({ triggered: true, id, result });
}
