import { Request, Response } from 'express';
import * as simClient from '../../libs/similarity/client';

export async function getExport(req: Request, res: Response) {
  res.json({ ok: true, export: null });
}

export async function postExportReady(req: Request, res: Response) {
  res.json({ ok: true });
}

export async function getConfig(req: Request, res: Response) {
  res.json({ thresholds: {} });
}

export async function patchConfig(req: Request, res: Response) {
  res.json({ ok: true, patched: req.body });
}

// admin: build similarity index
export async function postBuildIndex(req: Request, res: Response) {
  const limit = req.body?.limit || 10000;
  try {
    const out = await simClient.buildIndex(limit);
    res.json({ ok: true, out });
  } catch (e: any) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
}

// admin: proxy search (useful for debugging)
export async function postSearch(req: Request, res: Response) {
  try {
    const { vector, text, top_k } = req.body || {};
    let out;
    if (vector) out = await simClient.searchByVector(vector, top_k || 10);
    else out = await simClient.searchByText(text || '', top_k || 10);
    res.json({ ok: true, out });
  } catch (e: any) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
}
