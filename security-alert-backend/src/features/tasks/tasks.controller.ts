import { Request, Response } from 'express';
export async function createTask(req: Request, res: Response) { res.json({ ok: true }); }
export async function listTasks(req: Request, res: Response) { res.json([]); }
export async function patchTask(req: Request, res: Response) { res.json({ patched: true }); }
