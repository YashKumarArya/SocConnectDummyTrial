import { setInterval } from 'timers';
import { ingestionRepo } from '../features/ingestion/ingestion.repo';
import { normalizationRepo } from '../features/normalization/normalization.repo';
import { normalizeHybrid } from '../common/normalizer.hybrid';

// Kafka consumer worker for normalization (stub)
export async function startNormalizeWorker() {
  console.log('Starting normalize worker (MVP poller)');

  async function poll() {
    try {
      const items = await ingestionRepo.listUnprocessed();
      for (const it of items) {
        try {
          const normalized = normalizeHybrid(it, { logUnmappedFields: false });
          await normalizationRepo.save(it.id, normalized);
          await ingestionRepo.markProcessed(it.id);
          console.log('Normalized', it.id);
        } catch (err) {
          console.error('normalize error for', it.id, err);
        }
      }
    } catch (err) {
      console.error('normalize poll error', err);
    }
  }

  // poll every 5s
  await poll();
  setInterval(poll, 5_000);
}
