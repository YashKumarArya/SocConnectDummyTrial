import { Router } from 'express';
import { postNormalized, triggerNormalize } from './normalization.controller';
import { normalizationService } from './normalization.service';

const router = Router();

router.post('/:id/normalized', postNormalized);
router.post('/normalize/trigger/:id', triggerNormalize);
router.get('/:id', async (req, res) => {
  const id = req.params.id;
  const rec = await normalizationService.get(id);
  if (!rec) return res.status(404).json({ error: 'not found' });
  res.json(rec);
});

export default router;
