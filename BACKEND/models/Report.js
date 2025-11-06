// FILE: cybershield-backend/models/Report.js
import mongoose from 'mongoose';

const PortInfoSchema = new mongoose.Schema({
  port: Number,
  protocol: String,
  state: String,
  service: String,
  product: String,
  version: String,
  extraInfo: String,
  risk: String, // 'critical', 'high', 'medium', 'low', 'info'
  riskScore: Number, // 0-100
  mitigation: String,
  cveList: [{
    cveId: String,
    cvss: Number,
    description: String,
  }],
});

const HostSchema = new mongoose.Schema({
  ip: String,
  hostname: String,
  state: String,
  os: String,
  ports: [PortInfoSchema],
  hostRiskScore: Number,
});

const ReportSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  jobId: {
    type: String,
    required: true,
    index: true,
  },
  target: {
    type: String,
    required: true,
  },
  scanType: {
    type: String,
    required: true,
  },
  hosts: [HostSchema],
  summary: {
    totalHosts: Number,
    hostsUp: Number,
    totalPorts: Number,
    openPorts: Number,
    criticalFindings: Number,
    highFindings: Number,
    mediumFindings: Number,
    lowFindings: Number,
  },
  riskScore: {
    type: Number,
    default: 0,
    min: 0,
    max: 100,
  },
  rawXml: {
    type: String,
  },
  nmapCommand: {
    type: String,
  },
  scanDuration: {
    type: Number, // seconds
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true,
  },
});

// Compound indexes for efficient queries
ReportSchema.index({ userId: 1, createdAt: -1 });
ReportSchema.index({ riskScore: -1 });

export default mongoose.model('Report', ReportSchema);