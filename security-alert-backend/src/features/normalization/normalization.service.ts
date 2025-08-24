import { normalizeHybrid } from '../../common/normalizer.hybrid';
import { normalizationRepo } from './normalization.repo';
import clickhouse from '../../libs/clickhouse/client';
import { postTriage } from '../../libs/triage';
import { fromTriageToWideRow, insertTriageWide } from '../../libs/clickhouse/insert_model_scores';

export const normalizationService = {
  async normalize(id: string, raw: any, sourceType?: string, options = {}) {
    // helper: build a 1.json-like flattened payload for triage from either the original raw or the v4 row
    function buildTriageJson(origObj: any, normalizedObj: any) {
      // If origObj already looks like the 1.json (has dotted keys or file.name), return as-is
      if (!origObj) origObj = {};
      const looksLikeSample = typeof origObj === 'object' && (origObj['file.name'] || origObj.file || origObj.id);
      if (looksLikeSample) return (typeof origObj === 'string') ? origObj : JSON.stringify(origObj, null, 2);

      // Prefer the normalized nested OCSF output when available
      if (normalizedObj && typeof normalizedObj === 'object') return JSON.stringify(normalizedObj, null, 2);

      return JSON.stringify(origObj || {}, null, 2);
    }

    const normalized = normalizeHybrid(raw, { logUnmappedFields: false }, sourceType);
    await normalizationRepo.save(id, normalized);

    // prepare a best-effort original object to populate ClickHouse columns
    const orig = raw || normalized.original || {};

    try {
      const row = {
        alpha_id: orig?.alpha_id || orig?.alphaId || id,
        // existing minimal normalized row for alerts_normalized table
        alert_id: id,
        vendor: orig?.vendor || null,
        product: orig?.product || null,
        severity: (normalized as any).event?.severity || orig?.severity || null,
        category: (normalized as any).event?.type || orig?.event || null,
        event_action: (normalized as any).event?.action || orig?.action || null,
        source_ip: (normalized as any).src?.ip || orig?.source?.ip || orig?.src_ip || orig?.src || null,
        dest_ip: (normalized as any).dst?.ip || orig?.destination?.ip || orig?.dst_ip || null,
        src_username: (normalized as any).user?.name || null,
        dest_username: null,
        file_name: (normalized as any).file?.name || null,
        file_hash: (normalized as any).file?.hash || null,
        url: (normalized as any).event?.url || orig?.url || null,
        email_from: (normalized as any).email?.sender || orig?.email?.from || null,
        email_to: (normalized as any).email?.recipient || orig?.email?.to || null,
        email_subject: (normalized as any).email?.subject || orig?.email?.subject || null,
        timestamp: (normalized as any).timestamp || orig?.timestamp || new Date().toISOString(),
        normalized: normalized,
        embedding_id: null
      };

      await clickhouse.insertNormalized([row]);

      // Post triage payload (compact) to configured triage endpoint (best-effort)
      try {
        const triagePayload = {
          id: row.alert_id || id,
          alpha_id: row.alpha_id,
          // attach raw alert JSON or the normalized nested object for triage
          triage_file_content: buildTriageJson(orig, normalized),
          triage_file_name: `${row.alpha_id}.json`,
          triage_file_content_type: 'application/json',
           file: {
             name: (normalized as any).file?.name || row.file_name || null,
             path: (normalized as any).file?.path || orig?.file_path || (orig && (orig.file && orig.file.path)) || null,
             hashes: { sha256: (normalized as any).file?.hash?.sha256 ?? (normalized as any).file?.hash ?? orig?.sha256 ?? null, sha1: (normalized as any).file?.hash?.sha1 ?? orig?.sha1 ?? null }
           },
           file_name: (normalized as any).file?.name || row.file_name || null,
           sha256: (normalized as any).file?.hash?.sha256 ?? orig?.sha256 ?? null,
           sha1: (normalized as any).file?.hash?.sha1 ?? orig?.sha1 ?? null,
           file_path: (normalized as any).file?.path || orig?.file_path || (orig && (orig.file && orig.file.path)) || null,
           severity_id: (normalized as any).threat?.severity || orig?.severity_id || null,
           threat_name: (normalized as any).threat?.name || orig?.threat_name || null,
           source_vendor: row.vendor || null,
           source_product: row.product || null,
           event_time: (normalized as any).timestamp || row.timestamp || null
         };

         console.log('triagePayload:', JSON.stringify(triagePayload, null, 2));

         const triageResp = await postTriage(triagePayload);
         console.log('triageResp:', JSON.stringify(triageResp, null, 2));
         if (triageResp) {
           try {
             const wide = fromTriageToWideRow(String(row.alert_id || ''), String(row.alpha_id || ''), triageResp as any, { v4_fields_present: undefined });
             console.log('triageWideRow:', JSON.stringify(wide, null, 2));
             await insertTriageWide([wide]);
           } catch (e: any) {
             console.error('insertTriageWide failed', e?.message || e);
           }
         }
       } catch (e: any) {
         console.error('postTriage failed', e?.message || e);
       }

    } catch (err: any) {
      console.error('clickhouse persist failed, writing to dlq', err?.message || err);
      try {
        await clickhouse.insertDLQ([
          {
            alpha_id: raw?.alpha_id || raw?.alphaId || id,
            alert_id: id,
            vendor: raw?.vendor || null,
            product: raw?.product || null,
            normalized: normalized,
            error_message: String(err?.message || err),
            attempts: 1,
            last_error_at: new Date().toISOString()
          }
        ], String(err?.message || err));
      } catch (e) {
        console.error('failed to write to clickhouse dlq', e);
      }
    }

    return normalized;
  },
  async get(id: string) {
    return normalizationRepo.get(id);
  }
};
