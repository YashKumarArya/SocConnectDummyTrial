import { Request, Response } from 'express';
import { computeS0ByEmbeddings, decideRouting } from './triage.service';

export async function postTriage(req: Request, res: Response) {
  const id = req.params.id;
  const raw = req.body;
  const severity = raw?.severity || raw?.event?.severity || 'unknown';
  const s0 = await computeS0ByEmbeddings(id, severity);
  const decision = decideRouting(s0);
  res.json({ id, s0, decision });
}
