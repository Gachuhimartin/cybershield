// FILE: cybershield-backend/routes/scanRoutes.js
import express from 'express';
import { createScan, getScanStatus } from '../controllers/scanController.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

router.post('/', authenticate, createScan);
router.get('/:jobId/status', authenticate, getScanStatus);

export default router;