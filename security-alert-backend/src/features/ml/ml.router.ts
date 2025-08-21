import { Router } from 'express';
import { postAgentOutput, postAggregate } from './ml.controller';
const router = Router();
router.post('/:id/agent-output', postAgentOutput);
router.post('/:id/aggregate-score', postAggregate);
export default router;
