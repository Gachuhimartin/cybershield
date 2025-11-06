// FILE: cybershield-backend/utils/riskMapper.js
import axios from 'axios';

// Risk scoring thresholds
const RISK_LEVELS = {
  CRITICAL: { min: 80, label: 'critical' },
  HIGH: { min: 60, label: 'high' },
  MEDIUM: { min: 40, label: 'medium' },
  LOW: { min: 20, label: 'low' },
  INFO: { min: 0, label: 'info' },
};

// Known vulnerable services and versions
const VULNERABLE_SERVICES = {
  'ssh': {
    vulnerableVersions: ['OpenSSH 7.4', 'OpenSSH 7.3', 'OpenSSH 6.6'],
    baseRisk: 40,
    mitigation: 'Update OpenSSH to version 8.0 or later. Disable password authentication and use key-based authentication only.',
  },
  'http': {
    baseRisk: 30,
    mitigation: 'Ensure HTTP is redirecting to HTTPS. Implement security headers (HSTS, CSP, X-Frame-Options).',
  },
  'https': {
    baseRisk: 20,
    mitigation: 'Review SSL/TLS configuration. Disable weak ciphers and protocols (SSLv3, TLS 1.0, TLS 1.1).',
  },
  'ftp': {
    baseRisk: 70,
    mitigation: 'FTP transmits credentials in plaintext. Replace with SFTP or FTPS. Disable anonymous access.',
  },
  'telnet': {
    baseRisk: 90,
    mitigation: 'Telnet is highly insecure. Disable immediately and use SSH instead.',
  },
  'smb': {
    vulnerableVersions: ['Samba 3.', 'Samba 4.0', 'Samba 4.1', 'Samba 4.2', 'Samba 4.3', 'Samba 4.4'],
    baseRisk: 75,
    mitigation: 'Update Samba to latest version. Check for MS17-010 (EternalBlue) vulnerability. Disable SMBv1.',
  },
  'mysql': {
    baseRisk: 50,
    mitigation: 'Ensure MySQL is not exposed to the internet. Use strong passwords and disable remote root login.',
  },
  'postgresql': {
    baseRisk: 50,
    mitigation: 'Restrict PostgreSQL access to localhost or trusted IPs only. Use SSL/TLS for connections.',
  },
  'redis': {
    baseRisk: 80,
    mitigation: 'Redis should never be exposed to the internet. Bind to localhost, enable authentication, and use firewall rules.',
  },
  'mongodb': {
    baseRisk: 75,
    mitigation: 'Enable authentication, bind to localhost, and use IP whitelisting. Update to latest version.',
  },
  'rdp': {
    baseRisk: 70,
    mitigation: 'Use strong passwords, enable NLA (Network Level Authentication), and restrict access via firewall. Consider using VPN.',
  },
  'vnc': {
    baseRisk: 75,
    mitigation: 'VNC transmits data unencrypted by default. Use SSH tunneling or switch to more secure remote access.',
  },
};

// Port-based risk assessment
const HIGH_RISK_PORTS = [
  { port: 23, service: 'telnet', risk: 90 },
  { port: 21, service: 'ftp', risk: 70 },
  { port: 445, service: 'smb', risk: 75 },
  { port: 139, service: 'netbios', risk: 70 },
  { port: 3389, service: 'rdp', risk: 70 },
  { port: 5900, service: 'vnc', risk: 75 },
  { port: 6379, service: 'redis', risk: 80 },
  { port: 27017, service: 'mongodb', risk: 75 },
  { port: 3306, service: 'mysql', risk: 60 },
  { port: 5432, service: 'postgresql', risk: 60 },
];

// Enrich host data with risk assessment
export async function enrichWithRiskData(hosts) {
  const vulnersApiKey = process.env.VULNERS_API_KEY;

  for (const host of hosts) {
    let hostMaxRisk = 0;

    for (const port of host.ports) {
      // Base risk assessment
      const riskData = assessPortRisk(port);
      port.risk = riskData.risk;
      port.riskScore = riskData.riskScore;
      port.mitigation = riskData.mitigation;

      // Enhance with CVE data if API key is available
      if (vulnersApiKey && port.product && port.version) {
        try {
          const cveData = await fetchCVEData(port.product, port.version, vulnersApiKey);
          if (cveData && cveData.length > 0) {
            port.cveList = cveData;
            
            // Increase risk score based on CVEs
            const maxCVSS = Math.max(...cveData.map(cve => cve.cvss || 0));
            port.riskScore = Math.min(100, port.riskScore + maxCVSS * 5);
            port.risk = getRiskLevel(port.riskScore);
          }
        } catch (error) {
          console.log(`   Warning: CVE lookup failed for ${port.product}: ${error.message}`);
        }
      }

      // Track maximum risk for host
      if (port.riskScore > hostMaxRisk) {
        hostMaxRisk = port.riskScore;
      }
    }

    host.hostRiskScore = hostMaxRisk;
  }

  return hosts;
}

// Assess risk for a single port
function assessPortRisk(port) {
  let riskScore = 10; // Base score for any open port
  let mitigation = 'Review the necessity of this service. Close if not required.';

  // Check if port is in high-risk list
  const highRiskPort = HIGH_RISK_PORTS.find(hrp => hrp.port === port.port);
  if (highRiskPort) {
    riskScore = highRiskPort.risk;
  }

  // Check service-specific risks
  const serviceName = port.service.toLowerCase();
  for (const [service, data] of Object.entries(VULNERABLE_SERVICES)) {
    if (serviceName.includes(service)) {
      riskScore = Math.max(riskScore, data.baseRisk);
      mitigation = data.mitigation;

      // Check for known vulnerable versions
      if (data.vulnerableVersions && port.version) {
        const isVulnerable = data.vulnerableVersions.some(vulnVer => 
          port.version.includes(vulnVer)
        );
        if (isVulnerable) {
          riskScore = Math.min(100, riskScore + 20);
          mitigation = `VULNERABLE VERSION DETECTED! ${mitigation}`;
        }
      }
      break;
    }
  }

  // Increase risk for services with no version info (might be hidden/outdated)
  if (!port.version && port.service && port.service !== 'unknown') {
    riskScore = Math.min(100, riskScore + 10);
  }

  // Check for TLS/SSL issues based on service
  if (serviceName.includes('https') || serviceName.includes('ssl')) {
    // This would ideally come from NSE scripts
    mitigation += ' Verify TLS configuration with ssl-enum-ciphers script.';
  }

  return {
    risk: getRiskLevel(riskScore),
    riskScore,
    mitigation,
  };
}

// Get risk level label from score
function getRiskLevel(score) {
  if (score >= RISK_LEVELS.CRITICAL.min) return RISK_LEVELS.CRITICAL.label;
  if (score >= RISK_LEVELS.HIGH.min) return RISK_LEVELS.HIGH.label;
  if (score >= RISK_LEVELS.MEDIUM.min) return RISK_LEVELS.MEDIUM.label;
  if (score >= RISK_LEVELS.LOW.min) return RISK_LEVELS.LOW.label;
  return RISK_LEVELS.INFO.label;
}

// Fetch CVE data from Vulners API
async function fetchCVEData(product, version, apiKey) {
  try {
    const query = `${product} ${version}`;
    const response = await axios.post(
      'https://vulners.com/api/v3/burp/software/',
      {
        software: product,
        version: version,
        type: 'software',
        maxVulnerabilities: 10,
      },
      {
        headers: {
          'Content-Type': 'application/json',
        },
        params: {
          apiKey,
        },
        timeout: 10000,
      }
    );

    if (response.data && response.data.data && response.data.data.search) {
      const vulns = response.data.data.search;
      return vulns.slice(0, 5).map(vuln => ({
        cveId: vuln.id || vuln._source?.id || 'N/A',
        cvss: vuln.cvss?.score || vuln._source?.cvss?.score || 0,
        description: vuln.description || vuln._source?.description || 'No description available',
      }));
    }

    return [];
  } catch (error) {
    // Silently fail CVE lookups - they're optional
    return [];
  }
}