// FILE: cybershield-backend/utils/nmap.js
import { spawn } from 'child_process';
import { sanitizeTarget } from './validation.js';

// Build nmap arguments based on scan type
export function buildNmapArgs(target, scanType, customArgs = '') {
  const args = [];
  const safeMode = process.env.SAFE_MODE !== 'false';
  const aggressiveMode = process.env.AGGRESSIVE_MODE === 'true';

  // Sanitize target
  target = sanitizeTarget(target);

  switch (scanType) {
    case 'discovery':
      // Host discovery only, no port scanning
      args.push('-sn', '-PE', '-PP', '-PM');
      break;

    case 'unauthenticated':
      // SYN scan with version detection, all ports
      args.push('-sS', '-sV', '-Pn', '-p-', '--version-intensity', '5');
      
      if (aggressiveMode && !safeMode) {
        args.push('--script', 'default,vuln');
      }
      break;

    case 'full':
      // Comprehensive scan: SYN, version, OS detection, all ports
      args.push('-sS', '-sV', '-O', '-Pn', '-p-', '--version-intensity', '5');
      
      if (aggressiveMode && !safeMode) {
        args.push('--script', 'default,vuln,exploit');
        args.push('-A'); // Enable OS detection, version detection, script scanning
      } else {
        args.push('--script', 'default,safe');
      }
      break;

    case 'stealth':
      // Slow, stealthy scan to evade IDS/IPS
      args.push('-sS', '-T2', '-sV', '-Pn', '-p-', '-f');
      args.push('--randomize-hosts', '--data-length', '10');
      break;

    case 'compliance':
      // Security compliance checks (SSL, SMB, etc.)
      args.push('-sS', '-sV', '-Pn', '-p', '21,22,23,25,80,110,143,443,445,3389,8080');
      
      const complianceScripts = safeMode
        ? 'ssl-enum-ciphers,ssl-cert,ssh-auth-methods,http-security-headers'
        : 'ssl-enum-ciphers,ssl-cert,ssl-heartbleed,smb-enum-shares,smb-vuln-ms17-010,ssh-auth-methods,http-security-headers';
      
      args.push('--script', complianceScripts);
      break;

    case 'custom':
      // User-provided custom arguments
      if (!customArgs) {
        throw new Error('Custom scan requires arguments');
      }
      
      // Parse and sanitize custom args
      const customArgArray = customArgs.split(' ').filter(arg => arg.trim());
      
      // Security check: block dangerous flags in safe mode
      if (safeMode) {
        const dangerousArgs = ['--script-args', '--datadir', '--servicedb', '--spoof-mac'];
        const hasDangerous = customArgArray.some(arg => 
          dangerousArgs.some(dangerous => arg.startsWith(dangerous))
        );
        
        if (hasDangerous) {
          throw new Error('Custom scan contains prohibited arguments in SAFE_MODE');
        }
      }
      
      args.push(...customArgArray);
      break;

    default:
      throw new Error(`Unknown scan type: ${scanType}`);
  }

  // Always output XML to stdout
  args.push('-oX', '-');

  // Add timing template if not specified
  if (!args.some(arg => arg.startsWith('-T'))) {
    args.push('-T4'); // Aggressive timing by default
  }

  // Add target
  args.push(target);

  return args;
}

// Execute nmap scan
export function executeNmapScan(target, scanType, customArgs = '') {
  return new Promise((resolve, reject) => {
    try {
      const args = buildNmapArgs(target, scanType, customArgs);
      const command = `nmap ${args.join(' ')}`;

      console.log(`   Command: ${command}`);

      // Spawn nmap process
      const nmapProcess = spawn('nmap', args);

      let xmlOutput = '';
      let errorOutput = '';
      let settled = false;
      let timeoutId = null;

      nmapProcess.stdout.on('data', (data) => {
        xmlOutput += data.toString();
      });

      nmapProcess.stderr.on('data', (data) => {
        errorOutput += data.toString();
        console.log(`   Nmap stderr: ${data.toString().trim()}`);
      });

      nmapProcess.on('close', (code) => {
        if (timeoutId) clearTimeout(timeoutId);
        if (settled) return;
        settled = true;

        if (code !== 0) {
          const errorMsg = errorOutput || `Nmap exited with code ${code}`;
          console.error(`   Nmap error: ${errorMsg}`);
          return reject(new Error(`Nmap scan failed: ${errorMsg}`));
        }

        if (!xmlOutput || xmlOutput.trim().length === 0) {
          return reject(new Error('Nmap produced no output'));
        }

        resolve({
          xml: xmlOutput,
          command,
          stderr: errorOutput,
        });
      });

      nmapProcess.on('error', (error) => {
        if (timeoutId) clearTimeout(timeoutId);
        if (settled) return;
        settled = true;
        if (error.code === 'ENOENT') {
          reject(new Error('Nmap is not installed or not in PATH. Please install nmap first.'));
        } else {
          reject(new Error(`Failed to execute nmap: ${error.message}`));
        }
      });

      // Set timeout (30 minutes max)
      timeoutId = setTimeout(() => {
        if (settled) return;
        settled = true;
        try { nmapProcess.kill('SIGTERM'); } catch (e) {}
        reject(new Error('Scan timeout after 30 minutes'));
      }, 30 * 60 * 1000);

    } catch (error) {
      reject(error);
    }
  });
}