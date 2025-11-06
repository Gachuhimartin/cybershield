// FILE: cybershield-backend/README.md

# CyberShield Backend - Vulnerability Scanning Platform
```
═══════════════════════════════════════════════════════════════════
⚠️  CRITICAL SECURITY AND LEGAL WARNING ⚠️
═══════════════════════════════════════════════════════════════════

CyberShield is a POWERFUL vulnerability scanning tool that uses nmap
to perform network reconnaissance and security assessments.

LEGAL NOTICE - READ CAREFULLY:

✓ Only scan systems YOU OWN or have EXPLICIT WRITTEN PERMISSION to test
✗ Unauthorized scanning is ILLEGAL and may result in:
  • Criminal prosecution under CFAA (US), Computer Misuse Act (UK)
  • Civil liability
  • Network bans and blacklisting
  • Severe legal and financial consequences

RECOMMENDED SAFE SETTINGS:
- LAB_MODE=true  → Restricts scans to private IP ranges only
- SAFE_MODE=true → Disables intrusive/destructive scanning

USE AT YOUR OWN RISK. The authors assume NO LIABILITY for misuse.

═══════════════════════════════════════════════════════════════════
```

## Features

- **Multiple Scan Types**: Discovery, Unauthenticated, Full, Stealth, Compliance, and Custom
- **Real Nmap Integration**: Executes actual nmap scans with safe defaults
- **Risk Assessment**: Automatic vulnerability scoring and mitigation advice
- **CVE Enrichment**: Optional integration with Vulners API for CVE data
- **Job Queue System**: Asynchronous scan processing with BullMQ and Redis
- **User Authentication**: Secure JWT-based authentication
- **REST API**: Clean, well-documented endpoints
- **Lab-Safe Mode**: Restricts scanning to private IP ranges for demos/testing

## Tech Stack

- **Backend**: Node.js (ESM), Express.js
- **Database**: MongoDB (Mongoose)
- **Queue**: Redis + BullMQ
- **Security**: Helmet, CORS, bcryptjs, JWT, express-rate-limit
- **Scanning**: nmap (child_process spawn)
- **Parsing**: xml2js

## Prerequisites

### Ubuntu/Debian/Parrot OS
```bash
# Update package lists
sudo apt update

# Install Node.js (v18 or later)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install MongoDB
sudo apt install -y mongodb

# Install Redis
sudo apt install -y redis-server

# Install nmap
sudo apt install -y nmap

# Verify installations
node --version
npm --version
mongod --version
redis-server --version
nmap --version
```

## Installation
```bash
# Clone or create the project directory
mkdir cybershield-backend
cd cybershield-backend

# Copy all the provided files into this directory

# Install Node.js dependencies
npm install

# Create .env file from example
cp .env.example .env

# Edit .env with your settings
nano .env
```

## Configuration

Edit `.env` file:
```bash
# MongoDB (default local instance)
MONGO_URI=mongodb://localhost:27017/cybershield

# Redis (default local instance)
REDIS_URL=redis://localhost:6379

# JWT Secret (CHANGE THIS!)
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRE=7d

# Server
PORT=5000
NODE_ENV=development

# Security Settings
LAB_MODE=true              # KEEP THIS TRUE for demos/testing
SAFE_MODE=true             # KEEP THIS TRUE to prevent intrusive scans
AGGRESSIVE_MODE=false      # Set to true for intrusive NSE scripts (requires SAFE_MODE=false)

# Optional: Vulners API for CVE data
VULNERS_API_KEY=           # Leave empty to skip CVE lookups
```

## Running the Application

### Terminal 1: Start MongoDB (if not running as service)
```bash
sudo systemctl start mongodb
# OR
sudo mongod --dbpath /var/lib/mongodb
```

### Terminal 2: Start Redis (if not running as service)
```bash
sudo systemctl start redis-server
# OR
redis-server
```

### Terminal 3: Start the API Server
```bash
npm start
```

Expected output:
```
✅ MongoDB Connected: localhost
✅ Redis Connected
═══════════════════════════════════════════════════════════════════
⚠️  SECURITY WARNING: Only scan systems you own or have permission to test
═══════════════════════════════════════════════════════════════════

🚀 CyberShield Backend running on port 5000
📊 Environment: development
🔒 Lab Mode: ENABLED (Safe)
🛡️  Safe Mode: ENABLED
⚡ Aggressive Mode: DISABLED
```

### Terminal 4: Start the Scan Worker
```bash
npm run worker
```

Expected output:
```
✅ MongoDB Connected: localhost
═══════════════════════════════════════════════════════════════════
⚠️  SECURITY WARNING: Only scan systems you own or have permission to test
═══════════════════════════════════════════════════════════════════

🔧 CyberShield Scan Worker starting...
🔒 Lab Mode: ENABLED (Safe)
🛡️  Safe Mode: ENABLED
⚡ Aggressive Mode: DISABLED

✅ Worker is ready and listening for jobs
```

## API Endpoints

### Authentication

#### Register User
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'
```

Response:
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "673abc123def456789012345",
    "username": "testuser",
    "email": "test@example.com",
    "role": "user"
  }
}
```

#### Login
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'
```

#### Get Current User
```bash
curl -X GET http://localhost:5000/api/auth/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Scanning

#### Create Scan Job
```bash
# Discovery scan (host discovery only)
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "target": "192.168.1.1",
    "scanType": "discovery"
  }'

# Unauthenticated scan (SYN scan with version detection)
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "target": "192.168.1.0/24",
    "scanType": "unauthenticated"
  }'

# Full scan (comprehensive with OS detection)
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "target": "192.168.1.100",
    "scanType": "full"
  }'

# Custom scan (user-defined nmap arguments)
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "target": "192.168.1.1",
    "scanType": "custom",
    "customArgs": "-sn -PE"
  }'
```

Response:
```json
{
  "success": true,
  "message": "Scan job created and queued",
  "jobId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "target": "192.168.1.1",
  "scanType": "discovery",
  "status": "queued"
}
```

#### Check Scan Status
```bash
curl -X GET http://localhost:5000/api/scan/a1b2c3d4-e5f6-7890-abcd-ef1234567890/status \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

Response (in progress):
```json
{
  "success": true,
  "job": {
    "jobId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "target": "192.168.1.1",
    "scanType": "discovery",
    "status": "running",
    "progress": 50,
    "createdAt": "2025-11-04T10:30:00.000Z",
    "startedAt": "2025-11-04T10:30:05.000Z"
  }
}
```

Response (completed):
```json
{
  "success": true,
  "job": {
    "jobId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "target": "192.168.1.1",
    "scanType": "discovery",
    "status": "completed",
    "progress": 100,
    "reportId": "673def456abc789012345678",
    "createdAt": "2025-11-04T10:30:00.000Z",
    "startedAt": "2025-11-04T10:30:05.000Z",
    "completedAt": "2025-11-04T10:35:23.000Z"
  }
}
```

### Reports

#### List All Reports (Paginated)
```bash
curl -X GET "http://localhost:5000/api/reports?page=1&limit=10" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

Response:
```json
{
  "success": true,
  "reports": [
    {
      "_id": "673def456abc789012345678",
      "target": "192.168.1.1",
      "scanType": "discovery",
      "riskScore": 35,
      "summary": {
        "totalHosts": 1,
        "hostsUp": 1,
        "totalPorts": 5,
        "openPorts": 3,
        "criticalFindings": 0,
        "highFindings": 1,
        "mediumFindings": 2,
        "lowFindings": 2
      },
      "createdAt": "2025-11-04T10:35:23.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 15,
    "pages": 2
  }
}
```

#### Get Single Report
```bash
curl -X GET http://localhost:5000/api/reports/673def456abc789012345678 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

Response:
```json
{
  "success": true,
  "report": {
    "_id": "673def456abc789012345678",
    "userId": "673abc123def456789012345",
    "jobId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "target": "192.168.1.1",
    "scanType": "unauthenticated",
    "hosts": [
      {
        "ip": "192.168.1.1",
        "hostname": "router.local",
        "state": "up",
        "os": "Linux 3.2 - 4.9",
        "ports": [
          {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "7.4",
            "risk": "medium",
            "riskScore": 40,
            "mitigation": "Update OpenSSH to version 8.0 or later. Disable password authentication and use key-based authentication only.",
            "cveList": []
          },
          {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "product": "nginx",
            "version": "1.14.0",
            "risk": "medium",
            "riskScore": 35,
            "mitigation": "Ensure HTTP is redirecting to HTTPS. Implement security headers (HSTS, CSP, X-Frame-Options).",
            "cveList": []
          },
          {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "service": "https",
            "product": "nginx",
            "version": "1.14.0",
            "risk": "low",
            "riskScore": 25,
            "mitigation": "Review SSL/TLS configuration. Disable weak ciphers and protocols (SSLv3, TLS 1.0, TLS 1.1). Verify TLS configuration with ssl-enum-ciphers script.",
            "cveList": []
          }
        ],
        "hostRiskScore": 40
      }
    ],
    "summary": {
      "totalHosts": 1,
      "hostsUp": 1,
      "totalPorts": 3,
      "openPorts": 3,
      "criticalFindings": 0,
      "highFindings": 0,
      "mediumFindings": 2,
      "lowFindings": 1
    },
    "riskScore": 38,
    "nmapCommand": "nmap -sS -sV -Pn -p- --version-intensity 5 -oX - -T4 192.168.1.1",
    "scanDuration": 318,
    "createdAt": "2025-11-04T10:35:23.000Z"
  }
}
```

## Scan Types Explained

| Scan Type | Description | Nmap Args | Use Case |
|-----------|-------------|-----------|----------|
| **discovery** | Host discovery only, no port scanning | `-sn -PE` | Quick network mapping |
| **unauthenticated** | SYN scan with version detection, all ports | `-sS -sV -Pn -p-` | Standard vulnerability assessment |
| **full** | Comprehensive: SYN, version, OS detection | `-sS -sV -O -Pn -p-` | Deep security audit |
| **stealth** | Slow, evasive scan to avoid IDS/IPS | `-sS -T2 -sV -Pn -p- -f` | Red team operations |
| **compliance** | Security compliance checks (SSL, SMB, etc.) | `-sS -sV --script ssl-enum-ciphers,smb-enum-shares` | Compliance audits |
| **custom** | User-defined nmap arguments | Custom | Advanced users |

## Security Modes

### LAB_MODE (Target Restriction)
- **Enabled (true)**: Only allows scanning of private IP ranges:
  - `127.0.0.1` (localhost)
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
- **Disabled (false)**: Allows scanning any target (USE WITH CAUTION)

### SAFE_MODE (Script Restriction)
- **Enabled (true)**: Disables intrusive NSE scripts (exploit, dos, brute)
- **Disabled (false)**: Allows all NSE scripts

### AGGRESSIVE_MODE (Enhanced Scanning)
- **Enabled (true)**: Uses intrusive scripts for deeper scanning (requires SAFE_MODE=false)
- **Disabled (false)**: Standard scanning only

## Project Structure
```
cybershield-backend/
├── server.js                 # Main entry point
├── package.json              # Dependencies
├── .env                      # Environment configuration
├── .env.example              # Environment template
├── config/
│   ├── db.js                 # MongoDB connection
│   └── queue.js              # Redis + BullMQ setup
├── models/
│   ├── User.js               # User schema
│   ├── ScanJob.js            # Scan job schema
│   └── Report.js             # Scan report schema
├── routes/
│   ├── authRoutes.js         # Authentication routes
│   ├── scanRoutes.js         # Scan routes
│   └── reportRoutes.js       # Report routes
├── controllers/
│   ├── authController.js     # Auth logic
│   ├── scanController.js     # Scan logic
│   └── reportController.js   # Report logic
├── middleware/
│   └── auth.js               # JWT authentication
├── workers/
│   └── scanWorker.js         # Background scan processor
├── utils/
│   ├── validation.js         # Target validation & allowlist
│   ├── nmap.js               # Nmap command builder
│   ├── xmlParser.js          # XML to JSON parser
│   └── riskMapper.js         # Risk scoring & CVE lookup
└── README.md                 # This file
```

## Risk Scoring

Risk scores range from 0-100 and are categorized as:

- **Critical (80-100)**: Immediate action required
- **High (60-79)**: High priority, address soon
- **Medium (40-59)**: Moderate risk, plan remediation
- **Low (20-39)**: Low risk, monitor
- **Info (0-19)**: Informational only

### Factors Affecting Risk Score:
1. Service type (telnet, FTP = high risk)
2. Known vulnerable versions
3. CVE data (if Vulners API enabled)
4. Lack of encryption (HTTP vs HTTPS)
5. Exposed databases/management interfaces

## CVE Integration (Optional)

To enable CVE lookups:

1. Sign up for a free Vulners API key: https://vulners.com/
2. Add to `.env`:
```
   VULNERS_API_KEY=your_api_key_here
```
3. Restart server and worker

CVE data will automatically enrich scan reports with known vulnerabilities.

## Troubleshooting

### "Nmap is not installed"
```bash
sudo apt install nmap
```

### "MongoDB connection failed"
```bash
sudo systemctl start mongodb
# Check status
sudo systemctl status mongodb
```

### "Redis connection error"
```bash
sudo systemctl start redis-server
# Check status
sudo systemctl status redis-server
```

### "Permission denied" when scanning
- Run worker with sudo for raw socket scans (SYN):
```bash
  sudo npm run worker
```
- Or use connect scans instead: `-sT` (slower but doesn't require root)

### Worker not processing jobs
- Ensure Redis is running
- Check worker logs for errors
- Verify `REDIS_URL` in `.env` matches your Redis instance

### LAB_MODE blocking your target
- If testing on your own infrastructure outside private ranges
- Set `LAB_MODE=false` in `.env`
- **ENSURE YOU HAVE PERMISSION TO SCAN THE TARGET**

## Development
```bash
# Install with dev dependencies
npm install

# Run with auto-reload
npm run dev        # API server
npm run dev:worker # Worker process
```

## Production Deployment

1. **Set environment variables**:
```bash
   NODE_ENV=production
   LAB_MODE=true  # Keep enabled unless you have proper controls
   JWT_SECRET=long-random-string-here
```

2. **Use process manager**:
```bash
   npm install -g pm2
   pm2 start server.js --name cybershield-api
   pm2 start workers/scanWorker.js --name cybershield-worker
   pm2 save
   pm2 startup
```

3. **Enable MongoDB authentication**
4. **Use Redis with password**
5. **Set up reverse proxy (nginx)**
6. **Enable firewall rules**
7. **Use SSL/TLS certificates**

## License

MIT License - Use at your own risk.

## Disclaimer

This software is provided for AUTHORIZED SECURITY TESTING ONLY. The authors and contributors:

- Are NOT responsible for any misuse or damage
- Do NOT endorse illegal activities
- STRONGLY recommend using LAB_MODE for all testing
- Advise obtaining explicit written permission before scanning any network

**Unauthorized network scanning is illegal. You have been warned.**

---

## Quick Start Checklist
```bash
# 1. Install system dependencies
sudo apt update
sudo apt install -y nodejs npm mongodb redis-server nmap

# 2. Start services
sudo systemctl start mongodb
sudo systemctl start redis-server

# 3. Install Node dependencies
npm install

# 4. Configure environment
cp .env.example .env
nano .env  # Edit as needed

# 5. Start API server (Terminal 1)
npm start

# 6. Start worker (Terminal 2)
npm run worker

# 7. Test the API
# Register
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@test.com","password":"SecurePass123!"}'

# Save the token from response, then:
export TOKEN="your_token_here"

# Create scan
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target":"127.0.0.1","scanType":"discovery"}'

# Check status (use jobId from previous response)
curl -X GET http://localhost:5000/api/scan/YOUR_JOB_ID/status \
  -H "Authorization: Bearer $TOKEN"

# Get report (once completed)
curl -X GET http://localhost:5000/api/reports/REPORT_ID \
  -H "Authorization: Bearer $TOKEN"
```

**Happy (authorized) scanning! 🔒🔍**