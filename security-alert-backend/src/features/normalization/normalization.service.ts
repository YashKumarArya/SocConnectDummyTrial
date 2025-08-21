import { normalizeHybrid } from '../../common/normalizer.hybrid';
import { normalizationRepo } from './normalization.repo';
import clickhouse from '../../libs/clickhouse/client';

export const normalizationService = {
  async normalize(id: string, raw: any, sourceType?: string, options = {}) {
    const normalized = normalizeHybrid(raw, { logUnmappedFields: false }, sourceType);
    await normalizationRepo.save(id, normalized);

    // prepare a best-effort original object to populate ClickHouse columns
    const orig = raw || normalized.original || {};

    try {
      const row = {
        alpha_id: orig?.alpha_id || orig?.alphaId || id,
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
