import { Router } from 'express';
import { createTask, listTasks, patchTask } from './tasks.controller';
const router = Router();
router.post('/tasks', createTask);
router.get('/tasks', listTasks);
router.patch('/tasks/:id', patchTask);
export default router;
