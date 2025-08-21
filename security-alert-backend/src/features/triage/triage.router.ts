import { Router } from 'express';
import { postTriage } from './triage.controller';
const router = Router();
router.post('/:id/score/triage', postTriage);
export default router;
