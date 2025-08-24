import { Request, Response } from 'express';
import { ingestionRepo } from './ingestion.repo';
import { getPresignedUrl } from '../../libs/minio';
import { produce } from '../../libs/kafka';
import { TOPICS } from '../../config/topics';
import { insertEDR } from '../../libs/clickhouse/insert_edr';
import { sendRawWebhook } from '../../libs/webhook';
import { insertAlertsRaw } from '../../libs/clickhouse/insert_raw';
import { normalizationService } from '../normalization/normalization.service';

let isRunningNormalizationAll = false;

export async function postRawAlert(req: Request, res: Response) {
  const alert = req.body;
  // if (!alert || !alert.id) {
  //   return res.status(400).json({ error: 'missing id' });
  // }

  // Insert into ClickHouse raw table and obtain canonical alpha_id (may generate one)
  let alphaId: string | undefined;
  try {
    alphaId = await insertAlertsRaw(alert);
    // attach alpha_id to alert so subsequent flows use canonical id
    if (!alert.alpha_id) alert.alpha_id = alphaId;
  } catch (err: any) {
    console.error('insertAlertsRaw failed', err?.message || err);
    // continue: we'll still save raw locally and mark as failed for retries
  }

  const rec = await ingestionRepo.saveRaw(alert);

  // Quick guard: ensure saveRaw returned a record
  if (!rec) {
    return res.status(500).json({ ok: false, error: 'failed to save raw alert' });
  }

  // Kick off normalization for this record and for any other ingested alerts.
  // This runs in background and is best-effort (does not block the HTTP response).
  if (!isRunningNormalizationAll) {
    isRunningNormalizationAll = true;
    (async () => {
      try {
        try {
          await normalizationService.normalize(rec.id, rec.payload);
        } catch (e) {
          console.error('failed to normalize current record', rec.id, e);
        }

        // Normalize all alerts that have been ingested (best-effort backlog processing)
        for (const v of ingestionRepo._store.values()) {
          try {
            await normalizationService.normalize(v.id, v.payload);
          } catch (e) {
            console.error('normalize failed for', v.id, e);
          }
        }
      } finally {
        isRunningNormalizationAll = false;
      }
    })().catch((e) => console.error('background normalization failed', e));
  }

  // Attempt immediate persistence into ClickHouse (synchronous best-effort).
  // On success mark processed; on failure mark failed so workers can retry.
  try {
    await insertEDR(alert);
    await ingestionRepo.markProcessed(rec.id);
    // best-effort: notify outbound webhook of raw ingestion
    try { await sendRawWebhook(alert); } catch (e) { /* swallow */ }
    return res.status(201).json({ ok: true, id: alert.id, alpha_id: alert.alpha_id || alphaId, rec });
  } catch (err: any) {
    await ingestionRepo.markFailed(rec.id);
    return res.status(500).json({ ok: false, error: String(err?.message || err) });
  }
}

export async function getRawUploadUrl(req: Request, res: Response) {
  const key = `raw/${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const url = await getPresignedUrl(key);
  res.json({ url, key });
}
