// FILE: cybershield-backend/server.js
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import { connectDB } from './config/db.js';
import authRoutes from './routes/authRoutes.js';
import scanRoutes from './routes/scanRoutes.js';
import reportRoutes from './routes/reportRoutes.js';

dotenv.config();

// ═══════════════════════════════════════════════════════════════════
// ⚠️  CRITICAL SECURITY WARNING ⚠️
// ═══════════════════════════════════════════════════════════════════
// CyberShield is a powerful vulnerability scanning tool.
// 
// LEGAL NOTICE:
// - Only scan systems you OWN or have EXPLICIT WRITTEN PERMISSION to test
// - Unauthorized scanning is ILLEGAL and may violate:
//   * Computer Fraud and Abuse Act (CFAA) in the US
//   * Computer Misuse Act in the UK
//   * Similar laws in other jurisdictions
// 
// RECOMMENDED SETTINGS FOR LABS/DEMOS:
// - Set LAB_MODE=true to restrict scanning to private IP ranges only
// - Keep SAFE_MODE=true to prevent intrusive/destructive scans
// 
// USE AT YOUR OWN RISK. Authors assume NO liability.
// ═══════════════════════════════════════════════════════════════════

const app = express();

// Connect to MongoDB
connectDB();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    }
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// CORS
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true
}));

// Body parser with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    labMode: process.env.LAB_MODE === 'true',
    safeMode: process.env.SAFE_MODE !== 'false',
    aggressiveMode: process.env.AGGRESSIVE_MODE === 'true'
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/scan', scanRoutes);
app.use('/api/reports', reportRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  
  // Don't leak error details in production
  const message = process.env.NODE_ENV === 'production' 
    ? 'Internal server error' 
    : err.message;
  
  res.status(err.status || 500).json({
    error: message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log('\n' + '═'.repeat(70));
  console.log('⚠️  SECURITY WARNING: Only scan systems you own or have permission to test');
  console.log('═'.repeat(70));
  console.log(`\n🚀 CyberShield Backend running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔒 Lab Mode: ${process.env.LAB_MODE === 'true' ? 'ENABLED (Safe)' : 'DISABLED (Caution!)'}`);
  console.log(`🛡️  Safe Mode: ${process.env.SAFE_MODE !== 'false' ? 'ENABLED' : 'DISABLED'}`);
  console.log(`⚡ Aggressive Mode: ${process.env.AGGRESSIVE_MODE === 'true' ? 'ENABLED' : 'DISABLED'}`);
  console.log('\n' + '═'.repeat(70) + '\n');
});

export default app;