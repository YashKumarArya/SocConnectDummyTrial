import { Router } from 'express';
import { postEmbedding, getSimilar, postReindex } from './embeddings.controller';

const router = Router();

router.post('/:id/embedding', postEmbedding);
router.get('/:id/similar', getSimilar);
router.post('/faiss/reindex', postReindex);

export default router;
