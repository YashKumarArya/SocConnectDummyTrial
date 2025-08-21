import { Request, Response } from 'express';
import { normalizationService } from './normalization.service';
import { ingestionRepo } from '../ingestion/ingestion.repo';

export async function postNormalized(req: Request, res: Response) {
  const id = req.params.id;
  const body = req.body;
  if (!id) return res.status(400).json({ error: 'missing id' });

  // allow direct POST of normalized payload
  const result = await normalizationService.normalize(id, body, req.query.source as string | undefined);
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
