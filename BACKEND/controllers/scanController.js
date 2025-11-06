// FILE: cybershield-backend/controllers/scanController.js
import { v4 as uuidv4 } from 'uuid';
import ScanJob from '../models/ScanJob.js';
import { scanQueue } from '../config/queue.js';
import { isValidTarget, isAllowedTarget } from '../utils/validation.js';
import { body, validationResult } from 'express-validator';

// @route   POST /api/scan
// @desc    Create new scan job
// @access  Private
export const createScan = [
  body('target').trim().notEmpty().withMessage('Target is required'),
  body('scanType')
    .isIn(['discovery', 'unauthenticated', 'full', 'stealth', 'compliance', 'custom'])
    .withMessage('Invalid scan type'),
  body('customArgs').optional().trim(),

  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { target, scanType, customArgs = '' } = req.body;

      // Validate target format
      if (!isValidTarget(target)) {
        return res.status(400).json({ 
          error: 'Invalid target format. Provide a valid IP address, CIDR, or hostname.' 
        });
      }

      // Check allowlist if LAB_MODE is enabled
      if (!isAllowedTarget(target)) {
        return res.status(403).json({
          error: 'Target not allowed. LAB_MODE is enabled - only private IP ranges are permitted (127.0.0.1, 10.x.x.x, 192.168.x.x, 172.16-31.x.x)',
        });
      }

      // Validate custom args for custom scan type
      if (scanType === 'custom' && !customArgs) {
        return res.status(400).json({ 
          error: 'Custom scan type requires customArgs parameter' 
        });
      }

      // Generate unique job ID
      const jobId = uuidv4();

      // Create scan job in database
      const scanJob = await ScanJob.create({
        jobId,
        userId: req.user.id,
        target,
        scanType,
        customArgs: scanType === 'custom' ? customArgs : '',
        status: 'queued',
      });

      // Add job to queue
      await scanQueue.add('scan', {
        jobId,
        userId: req.user.id.toString(),
        target,
        scanType,
        customArgs: scanType === 'custom' ? customArgs : '',
      }, {
        jobId, // Use our jobId as Bull job ID for easier tracking
      });

      console.log(`📋 Scan job created: ${jobId} for target ${target} (${scanType})`);

      res.status(201).json({
        success: true,
        message: 'Scan job created and queued',
        jobId,
        target,
        scanType,
        status: 'queued',
      });
    } catch (error) {
      console.error('Create scan error:', error);
      res.status(500).json({ error: 'Failed to create scan job' });
    }
  },
];

// @route   GET /api/scan/:jobId/status
// @desc    Get scan job status
// @access  Private
export const getScanStatus = async (req, res) => {
  try {
    const { jobId } = req.params;

    const scanJob = await ScanJob.findOne({ jobId });

    if (!scanJob) {
      return res.status(404).json({ error: 'Scan job not found' });
    }

    // Verify ownership
    if (scanJob.userId.toString() !== req.user.id.toString()) {
      return res.status(403).json({ error: 'Not authorized to view this scan' });
    }

    res.status(200).json({
      success: true,
      job: {
        jobId: scanJob.jobId,
        target: scanJob.target,
        scanType: scanJob.scanType,
        status: scanJob.status,
        progress: scanJob.progress,
        errorMessage: scanJob.errorMessage,
        reportId: scanJob.reportId,
        createdAt: scanJob.createdAt,
        startedAt: scanJob.startedAt,
        completedAt: scanJob.completedAt,
      },
    });
  } catch (error) {
    console.error('Get scan status error:', error);
    res.status(500).json({ error: 'Failed to fetch scan status' });
  }
};