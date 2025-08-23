import { Request, Response } from 'express';
import { ingestionRepo } from './ingestion.repo';
import { getPresignedUrl } from '../../libs/minio';
import { produce } from '../../libs/kafka';
import { TOPICS } from '../../config/topics';
import { insertEDR } from '../../libs/clickhouse/insert_edr';
import { sendRawWebhook } from '../../libs/webhook';

export async function postRawAlert(req: Request, res: Response) {
  const alert = req.body;
  if (!alert || !alert.id) {
    return res.status(400).json({ error: 'missing id' });
  }

  const rec = await ingestionRepo.saveRaw(alert);

  // Quick guard: ensure saveRaw returned a record
  if (!rec) {
    return res.status(500).json({ ok: false, error: 'failed to save raw alert' });
  }

  // Attempt immediate persistence into ClickHouse (synchronous best-effort).
  // On success mark processed; on failure mark failed so workers can retry.
  try {
    await insertEDR(alert);
    await ingestionRepo.markProcessed(rec.id);
    // best-effort: notify outbound webhook of raw ingestion
    try { await sendRawWebhook(alert); } catch (e) { /* swallow */ }
    return res.status(201).json({ ok: true, id: alert.id, rec });
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
