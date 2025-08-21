import { Router } from 'express';
import { postLLMResult } from './llm.controller';
const router = Router();
router.post('/:id/llm-result', postLLMResult);
export default router;
