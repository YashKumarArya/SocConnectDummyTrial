import { Request, Response } from 'express';
export async function postAgentOutput(req: Request, res: Response) { res.json({ ok: true }); }
export async function postAggregate(req: Request, res: Response) { res.json({ aggregated: true }); }
