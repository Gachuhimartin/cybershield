// FILE: cybershield-backend/routes/reportRoutes.js
import express from 'express';
import { getReports, getReportById } from '../controllers/reportController.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

router.get('/', authenticate, getReports);
router.get('/:id', authenticate, getReportById);

export default router;