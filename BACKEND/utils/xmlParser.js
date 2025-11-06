// FILE: cybershield-backend/utils/xmlParser.js
import xml2js from 'xml2js';

// Parse nmap XML output into structured JSON
export async function parseNmapXML(xmlString) {
  try {
    const parser = new xml2js.Parser({
      explicitArray: false,
      mergeAttrs: true,
    });

    const result = await parser.parseStringPromise(xmlString);
    
    if (!result || !result.nmaprun) {
      throw new Error('Invalid nmap XML output');
    }

    const nmaprun = result.nmaprun;
    const hosts = [];

    // Handle single host or array of hosts
    const hostData = Array.isArray(nmaprun.host) ? nmaprun.host : [nmaprun.host].filter(Boolean);

    for (const host of hostData) {
      if (!host) continue;

      const hostInfo = {
        ip: '',
        hostname: '',
        state: 'unknown',
        os: '',
        ports: [],
        hostRiskScore: 0,
      };

      // Extract IP address
      if (host.address) {
        const addresses = Array.isArray(host.address) ? host.address : [host.address];
        const ipAddr = addresses.find(addr => addr.addrtype === 'ipv4' || addr.addrtype === 'ipv6');
        if (ipAddr) {
          hostInfo.ip = ipAddr.addr;
        }
      }

      // Extract hostname
      if (host.hostnames && host.hostnames.hostname) {
        const hostnames = Array.isArray(host.hostnames.hostname) 
          ? host.hostnames.hostname 
          : [host.hostnames.hostname];
        if (hostnames[0] && hostnames[0].name) {
          hostInfo.hostname = hostnames[0].name;
        }
      }

      // Extract host state
      if (host.status && host.status.state) {
        hostInfo.state = host.status.state;
      }

      // Extract OS information
      if (host.os && host.os.osmatch) {
        const osmatches = Array.isArray(host.os.osmatch) ? host.os.osmatch : [host.os.osmatch];
        if (osmatches[0] && osmatches[0].name) {
          hostInfo.os = osmatches[0].name;
        }
      }

      // Extract port information
      if (host.ports && host.ports.port) {
        const ports = Array.isArray(host.ports.port) ? host.ports.port : [host.ports.port];

        for (const port of ports) {
          const portInfo = {
            port: parseInt(port.portid) || 0,
            protocol: port.protocol || 'tcp',
            state: port.state?.state || 'unknown',
            service: '',
            product: '',
            version: '',
            extraInfo: '',
            risk: 'info',
            riskScore: 0,
            mitigation: '',
            cveList: [],
          };

          // Extract service information
          if (port.service) {
            portInfo.service = port.service.name || '';
            portInfo.product = port.service.product || '';
            portInfo.version = port.service.version || '';
            portInfo.extraInfo = port.service.extrainfo || '';
          }

          // Extract script output (NSE results)
          if (port.script) {
            const scripts = Array.isArray(port.script) ? port.script : [port.script];
            portInfo.scriptOutput = scripts.map(s => ({
              id: s.id,
              output: s.output,
            }));
          }

          hostInfo.ports.push(portInfo);
        }
      }

      hosts.push(hostInfo);
    }

    return hosts;

  } catch (error) {
    console.error('XML parsing error:', error);
    throw new Error(`Failed to parse nmap XML: ${error.message}`);
  }
}