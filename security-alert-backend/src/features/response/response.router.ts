import { Router } from 'express';
import { postAction, postResult } from './response.controller';
const router = Router();
router.post('/:id/response-action', postAction);
router.post('/:id/response-result', postResult);
export default router;
