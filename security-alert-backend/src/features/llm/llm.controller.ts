import { Request, Response } from 'express';
export async function postLLMResult(req: Request, res: Response) { res.json({ ok: true }); }
