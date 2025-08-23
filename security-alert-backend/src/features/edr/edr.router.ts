import { Router } from 'express';
import { getOCSF, getOCSFFlat, getAlertsSourceList } from './edr.controller';

const router = Router();
router.get('/alerts/:alphaId/ocsf', getOCSF);
router.get('/alerts/:alphaId/ocsf/flat', getOCSFFlat);
router.get('/alerts/sources', getAlertsSourceList);

export default router;
