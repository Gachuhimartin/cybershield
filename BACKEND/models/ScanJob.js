// FILE: cybershield-backend/models/ScanJob.js
import mongoose from 'mongoose';

const ScanJobSchema = new mongoose.Schema({
  jobId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  target: {
    type: String,
    required: true,
  },
  scanType: {
    type: String,
    enum: ['discovery', 'unauthenticated', 'full', 'stealth', 'compliance', 'custom'],
    required: true,
  },
  customArgs: {
    type: String,
    default: '',
  },
  status: {
    type: String,
    enum: ['queued', 'running', 'completed', 'failed'],
    default: 'queued',
    index: true,
  },
  progress: {
    type: Number,
    default: 0,
    min: 0,
    max: 100,
  },
  errorMessage: {
    type: String,
  },
  reportId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Report',
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true,
  },
  startedAt: {
    type: Date,
  },
  completedAt: {
    type: Date,
  },
});

// Compound index for user queries
ScanJobSchema.index({ userId: 1, createdAt: -1 });

export default mongoose.model('ScanJob', ScanJobSchema);