/**
 * Tool Configuration Definitions
 * Common flags and automation capabilities for penetration testing tools
 */

import { ToolConfig } from '@/components/ToolConfigurationForm';

export const toolConfigurations: Record<string, ToolConfig> = {
  nmap: {
    name: 'Nmap',
    description: 'Network discovery and security auditing utility',
    category: 'network',
    automationCapable: true,
    automationDescription: 'Can automatically progress from discovery to service enumeration to vulnerability scanning based on findings.',
    commonFlags: [
      // Basic flags
      {
        flag: '-sS',
        description: 'TCP SYN scan (default, requires root)',
        category: 'basic',
        type: 'boolean'
      },
      {
        flag: '-sT',
        description: 'TCP connect scan (no root required)',
        category: 'basic', 
        type: 'boolean',
        conflicts: ['-sS']
      },
      {
        flag: '-sU',
        description: 'UDP scan',
        category: 'basic',
        type: 'boolean'
      },
      {
        flag: '-p',
        description: 'Port specification',
        category: 'basic',
        type: 'string',
        examples: ['1-1000', '22,80,443', 'T:1-1000,U:53,161']
      },
      {
        flag: '-A',
        description: 'Aggressive scan (OS detection, version detection, script scanning, and traceroute)',
        category: 'basic',
        type: 'boolean'
      },
      
      // Advanced flags
      {
        flag: '-sV',
        description: 'Version detection',
        category: 'advanced',
        type: 'boolean'
      },
      {
        flag: '-O',
        description: 'OS detection',
        category: 'advanced',
        type: 'boolean'
      },
      {
        flag: '--script',
        description: 'NSE script execution',
        category: 'advanced',
        type: 'string',
        examples: ['default', 'vuln', 'safe', 'discovery', 'auth']
      },
      {
        flag: '--min-rate',
        description: 'Minimum packet rate',
        category: 'timing',
        type: 'number',
        defaultValue: 1000
      },
      {
        flag: '--max-rate',
        description: 'Maximum packet rate',
        category: 'timing',
        type: 'number',
        defaultValue: 10000
      },
      
      // Timing
      {
        flag: '-T',
        description: 'Timing template',
        category: 'timing',
        type: 'string',
        examples: ['0', '1', '2', '3', '4', '5']
      },
      
      // Evasion
      {
        flag: '-f',
        description: 'Fragment packets',
        category: 'evasion',
        type: 'boolean'
      },
      {
        flag: '--mtu',
        description: 'Set MTU size',
        category: 'evasion',
        type: 'number'
      },
      {
        flag: '-D',
        description: 'Decoy scan',
        category: 'evasion',
        type: 'string',
        examples: ['RND:10', 'ME,1.2.3.4,5.6.7.8']
      },
      
      // Output
      {
        flag: '-oA',
        description: 'Output all formats',
        category: 'output',
        type: 'string',
        examples: ['scan_results', 'nmap_output']
      },
      {
        flag: '-oN',
        description: 'Normal output',
        category: 'output',
        type: 'string'
      },
      {
        flag: '-oX',
        description: 'XML output',
        category: 'output',
        type: 'string'
      },
      {
        flag: '-v',
        description: 'Increase verbosity',
        category: 'output',
        type: 'boolean'
      }
    ],
    examples: {
      basic: 'nmap -sS -p 1-1000 192.168.1.0/24',
      intermediate: 'nmap -sS -sV -O -p- --script=default 192.168.1.1',
      advanced: 'nmap -sS -sU -sV -O -p- --script=vuln --min-rate=1000 -oA full_scan 192.168.1.0/24'
    }
  },

  sqlmap: {
    name: 'SQLMap',
    description: 'Automatic SQL injection and database takeover tool',
    category: 'web',
    automationCapable: true,
    automationDescription: 'Can automatically detect injection points, enumerate databases, extract data, and attempt privilege escalation.',
    commonFlags: [
      // Basic
      {
        flag: '-u',
        description: 'Target URL',
        category: 'basic',
        type: 'string',
        examples: ['http://example.com/page.php?id=1']
      },
      {
        flag: '--dbs',
        description: 'Enumerate databases',
        category: 'basic',
        type: 'boolean'
      },
      {
        flag: '--tables',
        description: 'Enumerate tables',
        category: 'basic',
        type: 'boolean'
      },
      {
        flag: '--columns',
        description: 'Enumerate columns',
        category: 'basic',
        type: 'boolean'
      },
      {
        flag: '--dump',
        description: 'Dump table entries',
        category: 'basic',
        type: 'boolean'
      },
      
      // Advanced
      {
        flag: '--level',
        description: 'Test level (1-5)',
        category: 'advanced',
        type: 'number',
        defaultValue: 1,
        examples: ['1', '2', '3', '4', '5']
      },
      {
        flag: '--risk',
        description: 'Risk level (1-3)',
        category: 'advanced',
        type: 'number',
        defaultValue: 1,
        examples: ['1', '2', '3']
      },
      {
        flag: '--technique',
        description: 'SQL injection techniques',
        category: 'advanced',
        type: 'string',
        examples: ['BEUSTQ', 'B', 'E', 'U', 'S', 'T', 'Q']
      },
      {
        flag: '--os-shell',
        description: 'Prompt for interactive OS shell',
        category: 'advanced',
        type: 'boolean'
      },
      
      // Timing
      {
        flag: '--delay',
        description: 'Delay between requests (seconds)',
        category: 'timing',
        type: 'number'
      },
      {
        flag: '--timeout',
        description: 'Connection timeout (seconds)',
        category: 'timing',
        type: 'number',
        defaultValue: 30
      },
      
      // Evasion
      {
        flag: '--random-agent',
        description: 'Use randomly selected User-Agent',
        category: 'evasion',
        type: 'boolean'
      },
      {
        flag: '--proxy',
        description: 'Use proxy server',
        category: 'evasion',
        type: 'string',
        examples: ['http://127.0.0.1:8080']
      },
      
      // Output
      {
        flag: '--batch',
        description: 'Never ask for user input',
        category: 'output',
        type: 'boolean'
      },
      {
        flag: '-v',
        description: 'Verbosity level (0-6)',
        category: 'output',
        type: 'number',
        defaultValue: 1
      }
    ],
    examples: {
      basic: 'sqlmap -u "http://example.com/page.php?id=1" --dbs',
      intermediate: 'sqlmap -u "http://example.com/page.php?id=1" --level=3 --risk=2 --batch --dbs',
      advanced: 'sqlmap -u "http://example.com/page.php?id=1" --level=5 --risk=3 --technique=BEUSTQ --random-agent --batch --os-shell'
    }
  },

  nikto: {
    name: 'Nikto',
    description: 'Web server vulnerability scanner',
    category: 'web',
    automationCapable: false,
    commonFlags: [
      // Basic
      {
        flag: '-h',
        description: 'Target host or URL',
        category: 'basic',
        type: 'string',
        examples: ['192.168.1.1', 'http://example.com']
      },
      {
        flag: '-p',
        description: 'Port number',
        category: 'basic',
        type: 'string',
        examples: ['80', '443', '80,443,8080']
      },
      {
        flag: '-ssl',
        description: 'Force SSL mode',
        category: 'basic',
        type: 'boolean'
      },
      
      // Advanced
      {
        flag: '-Tuning',
        description: 'Tuning options',
        category: 'advanced',
        type: 'string',
        examples: ['1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c']
      },
      {
        flag: '-Plugin',
        description: 'Select plugins',
        category: 'advanced',
        type: 'string',
        examples: ['@@ALL', '@@DEFAULT', 'apacheusers']
      },
      
      // Output
      {
        flag: '-o',
        description: 'Output file',
        category: 'output',
        type: 'string'
      },
      {
        flag: '-Format',
        description: 'Output format',
        category: 'output',
        type: 'string',
        examples: ['txt', 'xml', 'htm', 'csv']
      }
    ],
    examples: {
      basic: 'nikto -h http://example.com',
      intermediate: 'nikto -h http://example.com -p 80,443 -ssl -o nikto_results.txt',
      advanced: 'nikto -h http://example.com -Tuning 1,2,3,4,5,6,7,8,9 -Plugin @@ALL -Format xml -o nikto_comprehensive.xml'
    }
  },

  crackmapexec: {
    name: 'CrackMapExec',
    description: 'Network service exploitation and lateral movement tool',
    category: 'ad',
    automationCapable: true,
    automationDescription: 'Can automatically attempt credential spraying, lateral movement, and privilege escalation across Windows networks.',
    commonFlags: [
      // Basic
      {
        flag: 'smb',
        description: 'SMB protocol',
        category: 'basic',
        type: 'boolean'
      },
      {
        flag: 'ldap',
        description: 'LDAP protocol', 
        category: 'basic',
        type: 'boolean',
        conflicts: ['smb', 'winrm']
      },
      {
        flag: 'winrm',
        description: 'WinRM protocol',
        category: 'basic',
        type: 'boolean',
        conflicts: ['smb', 'ldap']
      },
      {
        flag: '-u',
        description: 'Username or username file',
        category: 'basic',
        type: 'string',
        examples: ['admin', 'users.txt']
      },
      {
        flag: '-p',
        description: 'Password or password file',
        category: 'basic',
        type: 'string',
        examples: ['password123', 'passwords.txt']
      },
      {
        flag: '-H',
        description: 'NTLM hash',
        category: 'basic',
        type: 'string',
        conflicts: ['-p']
      },
      
      // Advanced
      {
        flag: '--shares',
        description: 'Enumerate shares',
        category: 'advanced',
        type: 'boolean'
      },
      {
        flag: '--users',
        description: 'Enumerate users',
        category: 'advanced',
        type: 'boolean'
      },
      {
        flag: '--groups',
        description: 'Enumerate groups',
        category: 'advanced',
        type: 'boolean'
      },
      {
        flag: '--sam',
        description: 'Dump SAM hashes',
        category: 'advanced',
        type: 'boolean'
      },
      {
        flag: '--lsa',
        description: 'Dump LSA secrets',
        category: 'advanced',
        type: 'boolean'
      },
      
      // Timing
      {
        flag: '--threads',
        description: 'Number of threads',
        category: 'timing',
        type: 'number',
        defaultValue: 100
      },
      {
        flag: '--timeout',
        description: 'Connection timeout',
        category: 'timing',
        type: 'number',
        defaultValue: 20
      }
    ],
    examples: {
      basic: 'crackmapexec smb 192.168.1.0/24 -u admin -p password123',
      intermediate: 'crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt --shares',
      advanced: 'crackmapexec smb 192.168.1.0/24 -u admin -H aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 --sam --lsa --threads 50'
    }
  },

  bloodhound: {
    name: 'BloodHound',
    description: 'Active Directory attack path analysis tool',
    category: 'ad',
    automationCapable: true,
    automationDescription: 'Can automatically collect AD data, analyze attack paths, and suggest privilege escalation routes.',
    commonFlags: [
      // Basic (SharpHound collector)
      {
        flag: '-c',
        description: 'Collection methods',
        category: 'basic',
        type: 'string',
        examples: ['All', 'Default', 'DCOnly', 'Session,LoggedOn']
      },
      {
        flag: '-d',
        description: 'Domain to enumerate',
        category: 'basic',
        type: 'string',
        examples: ['CORP.LOCAL', 'DOMAIN.COM']
      },
      {
        flag: '--ldapusername',
        description: 'LDAP username',
        category: 'basic',
        type: 'string'
      },
      {
        flag: '--ldappassword',
        description: 'LDAP password',
        category: 'basic',
        type: 'string'
      },
      
      // Advanced
      {
        flag: '--stealth',
        description: 'Stealth collection mode',
        category: 'advanced',
        type: 'boolean'
      },
      {
        flag: '--computerfile',
        description: 'File with computer names',
        category: 'advanced',
        type: 'string'
      },
      {
        flag: '--excludedc',
        description: 'Exclude domain controllers',
        category: 'advanced',
        type: 'boolean'
      },
      
      // Output
      {
        flag: '--zipfilename',
        description: 'Zip file name',
        category: 'output',
        type: 'string',
        examples: ['bloodhound_data.zip']
      },
      {
        flag: '--randomizefilenames',
        description: 'Randomize output filenames',
        category: 'output',
        type: 'boolean'
      }
    ],
    examples: {
      basic: 'SharpHound.exe -c All -d CORP.LOCAL',
      intermediate: 'SharpHound.exe -c All -d CORP.LOCAL --ldapusername user --ldappassword pass --stealth',
      advanced: 'SharpHound.exe -c All,GPOLocalGroup -d CORP.LOCAL --stealth --excludedc --randomizefilenames --zipfilename corp_enum.zip'
    }
  },

  kdigger: {
    name: 'kdigger',
    description: 'Kubernetes runtime security assessment tool',
    category: 'kubernetes',
    automationCapable: true,
    automationDescription: 'Can automatically assess container escape vectors, privilege escalation paths, and cluster misconfigurations.',
    commonFlags: [
      // Basic
      {
        flag: 'dig',
        description: 'Run discovery mode',
        category: 'basic',
        type: 'boolean'
      },
      {
        flag: 'runtime',
        description: 'Assess container runtime',
        category: 'basic',
        type: 'boolean'
      },
      {
        flag: 'network',
        description: 'Network reconnaissance',
        category: 'basic',
        type: 'boolean'
      },
      
      // Advanced
      {
        flag: '--runtime',
        description: 'Container runtime type',
        category: 'advanced',
        type: 'string',
        examples: ['docker', 'containerd', 'crio']
      },
      {
        flag: '--namespace',
        description: 'Kubernetes namespace',
        category: 'advanced',
        type: 'string',
        defaultValue: 'default'
      },
      
      // Output
      {
        flag: '--output',
        description: 'Output format',
        category: 'output',
        type: 'string',
        examples: ['json', 'yaml', 'table']
      }
    ],
    examples: {
      basic: 'kdigger dig',
      intermediate: 'kdigger runtime --runtime docker --namespace default',
      advanced: 'kdigger dig runtime network --output json --namespace kube-system'
    }
  },

  kubehunter: {
    name: 'kube-hunter',
    description: 'Kubernetes security weakness discovery tool',
    category: 'kubernetes',
    automationCapable: false,
    commonFlags: [
      // Basic
      {
        flag: '--remote',
        description: 'Remote scanning mode',
        category: 'basic',
        type: 'string',
        examples: ['192.168.1.1', '10.0.0.0/8']
      },
      {
        flag: '--interface',
        description: 'Network interface for scanning',
        category: 'basic',
        type: 'string'
      },
      {
        flag: '--pod',
        description: 'Pod scanning mode',
        category: 'basic',
        type: 'boolean'
      },
      
      // Advanced
      {
        flag: '--active',
        description: 'Enable active hunting',
        category: 'advanced',
        type: 'boolean'
      },
      {
        flag: '--list',
        description: 'List available tests',
        category: 'advanced',
        type: 'boolean'
      },
      
      // Output
      {
        flag: '--report',
        description: 'Report format',
        category: 'output',
        type: 'string',
        examples: ['json', 'yaml']
      },
      {
        flag: '--log',
        description: 'Log level',
        category: 'output',
        type: 'string',
        examples: ['DEBUG', 'INFO', 'WARNING']
      }
    ],
    examples: {
      basic: 'kube-hunter --pod',
      intermediate: 'kube-hunter --remote 192.168.1.0/24 --report json',
      advanced: 'kube-hunter --remote 10.0.0.0/8 --active --report yaml --log DEBUG'
    }
  },

  spiderfoot: {
    name: 'SpiderFoot',
    description: 'Open Source Intelligence (OSINT) automation platform with 200+ modules',
    category: 'osint',
    automationCapable: true,
    automationDescription: 'Automatically correlates intelligence from multiple sources and provides recursive discovery capabilities.',
    commonFlags: [
      // Basic scan types
      {
        flag: '-s',
        description: 'Target to scan (domain, IP, netblock, etc.)',
        category: 'basic',
        type: 'string',
        examples: ['example.com', '192.168.1.1', '192.168.1.0/24']
      },
      {
        flag: '-m',
        description: 'Modules to use (comma-separated)',
        category: 'basic',
        type: 'string',
        examples: ['sfp_dnsresolve,sfp_whois', 'sfp_shodan,sfp_virustotal']
      },
      {
        flag: '-t',
        description: 'Scan type/template',
        category: 'basic',
        type: 'string',
        examples: ['footprint', 'investigate', 'passive', 'all']
      },
      
      // Output and format
      {
        flag: '-o',
        description: 'Output format',
        category: 'output',
        type: 'string',
        examples: ['json', 'csv', 'gexf', 'tab']
      },
      {
        flag: '-q',
        description: 'Quiet mode - minimal output',
        category: 'output',
        type: 'boolean'
      },
      {
        flag: '-l',
        description: 'Maximum number of results',
        category: 'advanced',
        type: 'string',
        examples: ['100', '500', '1000']
      },
      
      // Advanced options
      {
        flag: '-e',
        description: 'Event types to collect',
        category: 'advanced',
        type: 'string',
        examples: ['IP_ADDRESS', 'INTERNET_NAME', 'EMAILADDR']
      },
      {
        flag: '-f',
        description: 'Maximum depth for recursive scanning',
        category: 'advanced',
        type: 'string',
        examples: ['1', '3', '5']
      },
      {
        flag: '-n',
        description: 'Use DNS server',
        category: 'advanced',
        type: 'string',
        examples: ['8.8.8.8', '1.1.1.1']
      },
      {
        flag: '-p',
        description: 'HTTP proxy to use',
        category: 'advanced',
        type: 'string',
        examples: ['http://proxy:8080', 'socks5://127.0.0.1:9050']
      }
    ],
    examples: {
      basic: 'spiderfoot -s example.com -t footprint',
      intermediate: 'spiderfoot -s example.com -m sfp_dnsresolve,sfp_whois,sfp_shodan -o json',
      advanced: 'spiderfoot -s example.com -t investigate -f 3 -l 1000 -o json -p http://proxy:8080'
    }
  }
};