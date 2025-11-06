// FILE: cybershield-backend/utils/validation.js
import validator from 'validator';
import { isIP } from 'net';

// Validate target format (IP, CIDR, or hostname)
export function isValidTarget(target) {
  if (!target || typeof target !== 'string') {
    return false;
  }

  target = target.trim();

  // Check if it's a valid IP address
  if (isIP(target)) {
    return true;
  }

  // Check if it's a valid CIDR notation
  if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(target)) {
    const [ip, mask] = target.split('/');
    const maskNum = parseInt(mask);
    return isIP(ip) && maskNum >= 0 && maskNum <= 32;
  }

  // Check if it's a valid hostname/domain
  if (validator.isFQDN(target) || validator.isURL(`http://${target}`)) {
    return true;
  }

  // Allow IP ranges like 192.168.1.1-50
  if (/^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$/.test(target)) {
    return true;
  }

  return false;
}

// Check if target is in allowed list (for LAB_MODE)
export function isAllowedTarget(target) {
  // If LAB_MODE is disabled, allow all targets
  if (process.env.LAB_MODE !== 'true') {
    return true;
  }

  target = target.trim();

  // Extract IP from CIDR or range notation
  let ip = target;
  if (target.includes('/')) {
    ip = target.split('/')[0];
  } else if (target.includes('-')) {
    ip = target.split('-')[0];
  }

  // Allowed private IP ranges for lab testing
  const allowedRanges = [
    { prefix: '127.', description: 'Localhost' },
    { prefix: '10.', description: 'Private Class A' },
    { prefix: '192.168.', description: 'Private Class C' },
  ];

  // Check 172.16.0.0/12 range (172.16.x.x - 172.31.x.x)
  const parts = ip.split('.');
  if (parts.length === 4) {
    const first = parseInt(parts[0]);
    const second = parseInt(parts[1]);
    
    if (first === 172 && second >= 16 && second <= 31) {
      return true; // 172.16-31.x.x
    }
  }

  // Check other allowed ranges
  for (const range of allowedRanges) {
    if (ip.startsWith(range.prefix)) {
      return true;
    }
  }

  // Allow localhost hostnames
  const localhostNames = ['localhost', 'localhost.localdomain'];
  if (localhostNames.includes(target.toLowerCase())) {
    return true;
  }

  return false;
}

// Sanitize target string to prevent command injection
export function sanitizeTarget(target) {
  // Normalize and limit length
  if (typeof target !== 'string') return '';
  target = target.trim().replace(/\s+/g, ' ');

  // Remove any shell metacharacters and newlines
  return target.replace(/[;&|`$(){}[\]<>\\\n\r]/g, '');
}