import { Router } from 'express';
import { postVerdict, getVerdicts } from './verdicts.controller';
const router = Router();
router.post('/:id/verdict', postVerdict);
router.get('/:id/verdicts', getVerdicts);
export default router;
