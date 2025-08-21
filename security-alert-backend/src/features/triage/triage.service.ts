import { embeddingsRepo } from '../embeddings/embeddings.repo';
import { normalizationRepo } from '../normalization/normalization.repo';

export const triageService: { score: (id: string, fallbackSeverity?: string) => Promise<any> } = { async score() { return null } };

export async function computeS0ByEmbeddings(id: string, fallbackSeverity?: string) {
  // load normalized alert to access timestamp and severity
  const rec = await normalizationRepo.get(id);
  const severity = (rec?.normalized?.severity) || fallbackSeverity || 'unknown';

  // base mapping for severity
  const mapping: any = { critical: 95, high: 85, medium: 60, low: 30, unknown: 50 };
  const severityBase = mapping[severity.toLowerCase()] ?? 50;

  // similarity component
  try {
    const sims = await embeddingsRepo.getSimilarForAlert(id);
    if (sims && sims.length) {
      // sims expected: [{ score: number, meta: { ... } }]
      const meanSim = sims.reduce((s: number, x: any) => s + (x.score || 0), 0) / sims.length;
      // meanSim is inner product or cosine in range [-1,1] or positive — normalize to 0..1
      const normSim = Math.max(0, meanSim);
      const simScore = Math.round(Math.min(100, normSim * 100));

      // recency weight: recent alerts get slight boost
      let recencyFactor = 1.0;
      try {
        const ts = rec?.normalized?.timestamp || rec?.normalized?.created_at || null;
        if (ts) {
          const ageMs = Date.now() - new Date(ts).getTime();
          const ageHours = ageMs / (1000 * 60 * 60);
          // less than 24h -> 1.1, 24-72h ->1.0, older degrade to 0.8
          if (ageHours < 24) recencyFactor = 1.1;
          else if (ageHours < 72) recencyFactor = 1.0;
          else recencyFactor = 0.9;
        }
      } catch (e) {}

      // combine: weighted sum (similarity 60%, severity 40%) scaled by recency
      const combined = Math.round(Math.min(100, ((simScore * 0.6) + (severityBase * 0.4)) * recencyFactor));
      return combined;
    }
  } catch (err) {
    console.warn('embeddings lookup failed', err);
  }

  return severityBase;
}

export function decideRouting(s0: number) {
  if (s0 >= 79) return { route: 'verdict', s1: s0 };
  return { route: 'ml', s1: s0 };
}

// expose triageService.score to be used by controller
triageService.score = async function(id: string, fallbackSeverity?: string) {
  const s0 = await computeS0ByEmbeddings(id, fallbackSeverity);
  const decision = decideRouting(s0);
  return { id, s0, decision };
};
