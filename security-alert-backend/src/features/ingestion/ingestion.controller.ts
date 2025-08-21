import { Request, Response } from 'express';
import { ingestionRepo } from './ingestion.repo';
import { getPresignedUrl } from '../../libs/minio';
import { produce } from '../../libs/kafka';
import { TOPICS } from '../../config/topics';

export async function postRawAlert(req: Request, res: Response) {
  const alert = req.body;
  if (!alert || !alert.id) {
    return res.status(400).json({ error: 'missing id' });
  }

  const rec = await ingestionRepo.saveRaw(alert);

  res.status(201).json({ ok: true, id: alert.id, rec });
}

export async function getRawUploadUrl(req: Request, res: Response) {
  const key = `raw/${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const url = await getPresignedUrl(key);
  res.json({ url, key });
}
