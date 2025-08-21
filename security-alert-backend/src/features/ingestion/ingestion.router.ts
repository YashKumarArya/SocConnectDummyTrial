import { Router } from 'express';
import { postRawAlert, getRawUploadUrl } from './ingestion.controller';
import { idempotencyMiddleware } from '../../middleware/idempotency';

const router = Router();

router.post('/raw', idempotencyMiddleware, postRawAlert);
router.get('/raw-url', getRawUploadUrl);

export default router;
