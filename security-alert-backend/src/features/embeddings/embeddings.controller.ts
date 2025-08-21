import { Request, Response } from 'express';

export async function postEmbedding(req: Request, res: Response) { res.json({ ok: true }); }
export async function getSimilar(req: Request, res: Response) { res.json([]); }
export async function postReindex(req: Request, res: Response) { res.json({ started: true }); }
