// FILE: cybershield-backend/workers/scanWorker.js
import { Worker } from 'bullmq';
import dotenv from 'dotenv';
import { connectDB } from '../config/db.js';
import { redisConnection } from '../config/queue.js';
import ScanJob from '../models/ScanJob.js';
import Report from '../models/Report.js';
import { executeNmapScan } from '../utils/nmap.js';
import { parseNmapXML } from '../utils/xmlParser.js';
import { enrichWithRiskData } from '../utils/riskMapper.js';

dotenv.config();

// Connect to MongoDB
connectDB();

console.log('\n' + '═'.repeat(70));
console.log('⚠️  SECURITY WARNING: Only scan systems you own or have permission to test');
console.log('═'.repeat(70));
console.log(`\n🔧 CyberShield Scan Worker starting...`);
console.log(`🔒 Lab Mode: ${process.env.LAB_MODE === 'true' ? 'ENABLED (Safe)' : 'DISABLED (Caution!)'}`);
console.log(`🛡️  Safe Mode: ${process.env.SAFE_MODE !== 'false' ? 'ENABLED' : 'DISABLED'}`);
console.log(`⚡ Aggressive Mode: ${process.env.AGGRESSIVE_MODE === 'true' ? 'ENABLED' : 'DISABLED'}\n`);

// Create worker
const worker = new Worker('scan-jobs', async (job) => {
  const { jobId, userId, target, scanType, customArgs } = job.data;

  console.log(`\n🔍 Processing scan job: ${jobId}`);
  console.log(`   Target: ${target}`);
  console.log(`   Type: ${scanType}`);

  try {
    // Update job status to running
    await ScanJob.findOneAndUpdate(
      { jobId },
      { 
        status: 'running', 
        startedAt: new Date(),
        progress: 10 
      }
    );

    await job.updateProgress(10);

    // Execute nmap scan
    console.log(`   Executing nmap scan...`);
    const startTime = Date.now();
    
    const { xml, command, stderr } = await executeNmapScan(target, scanType, customArgs);
    
    const scanDuration = Math.round((Date.now() - startTime) / 1000);
    console.log(`   Scan completed in ${scanDuration}s`);

    await job.updateProgress(50);
    await ScanJob.findOneAndUpdate({ jobId }, { progress: 50 });

    // Parse XML results
    console.log(`   Parsing results...`);
    const parsedData = await parseNmapXML(xml);

    // Fix: single-line updateProgress call
    await job.updateProgress(70);
    await ScanJob.findOneAndUpdate({ jobId }, { progress: 70 });

    // Enrich with risk assessment
    console.log(`   Performing risk assessment...`);
    const enrichedData = await enrichWithRiskData(parsedData);

    await job.updateProgress(90);
    await ScanJob.findOneAndUpdate({ jobId }, { progress: 90 });

    // Calculate overall risk score
    const riskScore = calculateOverallRiskScore(enrichedData);

    // Calculate summary statistics
    const summary = calculateSummary(enrichedData);

    // Save report to database
    const report = await Report.create({
      userId,
      jobId,
      target,
      scanType,
      hosts: enrichedData,
      summary,
      riskScore,
      rawXml: xml,
      nmapCommand: command,
      scanDuration,
    });

    console.log(`   Report saved: ${report._id}`);

    // Update job status to completed
    await ScanJob.findOneAndUpdate(
      { jobId },
      {
        status: 'completed',
        completedAt: new Date(),
        reportId: report._id,
        progress: 100,
      }
    );

    await job.updateProgress(100);

    console.log(`✅ Scan job ${jobId} completed successfully`);

    return {
      success: true,
      reportId: report._id.toString(),
    };

  } catch (error) {
    console.error(`❌ Scan job ${jobId} failed:`, error.message);

    // Update job status to failed
    await ScanJob.findOneAndUpdate(
      { jobId },
      {
        status: 'failed',
        completedAt: new Date(),
        errorMessage: error.message,
      }
    );

    throw error;
  }
}, {
  connection: redisConnection,
  concurrency: 3, // Process up to 3 scans concurrently
  limiter: {
    max: 10,
    duration: 60000, // Max 10 jobs per minute
  },
});

// Calculate overall risk score based on findings
function calculateOverallRiskScore(hosts) {
  if (!hosts || hosts.length === 0) return 0;

  let totalScore = 0;
  let portCount = 0;

  hosts.forEach(host => {
    if (host.ports && host.ports.length > 0) {
      host.ports.forEach(port => {
        if (port.riskScore) {
          totalScore += port.riskScore;
          portCount++;
        }
      });
    }
  });

  if (portCount === 0) return 0;

  // Average risk score across all ports
  const averageScore = totalScore / portCount;

  // Boost score if there are many findings
  const volumeMultiplier = Math.min(1 + (portCount / 100), 1.5);

  return Math.min(Math.round(averageScore * volumeMultiplier), 100);
}

// Calculate summary statistics
function calculateSummary(hosts) {
  const summary = {
    totalHosts: hosts.length,
    hostsUp: 0,
    totalPorts: 0,
    openPorts: 0,
    criticalFindings: 0,
    highFindings: 0,
    mediumFindings: 0,
    lowFindings: 0,
  };

  hosts.forEach(host => {
    if (host.state === 'up') {
      summary.hostsUp++;
    }

    if (host.ports && host.ports.length > 0) {
      summary.totalPorts += host.ports.length;

      host.ports.forEach(port => {
        if (port.state === 'open') {
          summary.openPorts++;
        }

        switch (port.risk) {
          case 'critical':
            summary.criticalFindings++;
            break;
          case 'high':
            summary.highFindings++;
            break;
          case 'medium':
            summary.mediumFindings++;
            break;
          case 'low':
            summary.lowFindings++;
            break;
        }
      });
    }
  });

  return summary;
}

// Worker event handlers
worker.on('completed', (job) => {
  console.log(`✅ Job ${job.id} completed`);
});

worker.on('failed', (job, err) => {
  console.error(`❌ Job ${job?.id} failed:`, err.message);
});

worker.on('error', (err) => {
  console.error('Worker error:', err);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('\n⚠️  SIGTERM received, shutting down worker gracefully...');
  await worker.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('\n⚠️  SIGINT received, shutting down worker gracefully...');
  await worker.close();
  process.exit(0);
});

console.log('✅ Worker is ready and listening for jobs\n');