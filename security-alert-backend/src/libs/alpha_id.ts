import { v4 as uuidv4 } from 'uuid';

/**
 * Resolve or generate a canonical alpha_id for an alert
 * - Prefer explicit alpha_id / alphaId / id from the payload
 * - Otherwise use crypto.randomUUID() if available, else fall back to uuidv4()
 */
export function generateAlphaId(payload?: any): string {
  if (payload) {
    if (typeof payload.alpha_id === 'string' && payload.alpha_id) return payload.alpha_id;
    if (typeof payload.alphaId === 'string' && payload.alphaId) return payload.alphaId;
    if (typeof payload.id === 'string' && payload.id) return payload.id;
  }

  // Prefer native crypto.randomUUID when available
  try {
    const c: any = (globalThis as any).crypto;
    if (c && typeof c.randomUUID === 'function') return c.randomUUID();
  } catch (e) {
    // ignore
  }

  return uuidv4();
}

export default { generateAlphaId };
