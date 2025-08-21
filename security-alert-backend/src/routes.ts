import { Router } from 'express';
import ingestionRouter from './features/ingestion/ingestion.router';
import normalizationRouter from './features/normalization/normalization.router';
import embeddingsRouter from './features/embeddings/embeddings.router';
import triageRouter from './features/triage/triage.router';
import mlRouter from './features/ml/ml.router';
import llmRouter from './features/llm/llm.router';
import verdictsRouter from './features/verdicts/verdicts.router';
import tasksRouter from './features/tasks/tasks.router';
import responseRouter from './features/response/response.router';
import adminRouter from './features/admin/admin.router';

const router = Router();

// Mount feature routers
router.use('/ingestion', ingestionRouter);
router.use('/normalization', normalizationRouter);
router.use('/embeddings', embeddingsRouter);
router.use('/triage', triageRouter);
router.use('/ml', mlRouter);
router.use('/llm', llmRouter);
router.use('/verdicts', verdictsRouter);
router.use('/', tasksRouter); // tasks at /api/tasks
router.use('/', responseRouter);
router.use('/admin', adminRouter);

router.get('/healthz', (_, res) => res.status(200).send('ok'));

export default router;
