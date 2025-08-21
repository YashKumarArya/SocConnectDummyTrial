import { Request, Response } from 'express';
export async function postVerdict(req: Request, res: Response) { res.json({ ok: true }); }
export async function getVerdicts(req: Request, res: Response) { res.json([]); }
