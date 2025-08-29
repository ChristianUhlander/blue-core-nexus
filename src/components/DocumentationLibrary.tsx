/**
 * Comprehensive Documentation Library
 * Complete guide to the IPS Security Center platform
 * 
 * FEATURES:
 * ✅ Interactive documentation with code examples
 * ✅ Step-by-step tutorials and guides
 * ✅ API reference and integration docs
 * ✅ QA procedures and expected outcomes
 * ✅ Troubleshooting and FAQ sections
 * ✅ Best practices and security guidelines
 */

import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { 
  Book, 
  FileText, 
  Code, 
  Terminal, 
  Shield, 
  Zap, 
  Settings, 
  HelpCircle, 
  CheckCircle, 
  AlertTriangle,
  Search,
  ExternalLink,
  Play,
  Copy,
  Download,
  Bookmark,
  Star,
  Clock,
  Users,
  Cpu,
  Database,
  Network,
  Lock,
  Eye,
  Target,
  Bug,
  Wrench,
  GitBranch,
  Rocket,
  BarChart3,
  Info,
  ArrowRight,
  ChevronRight,
  Monitor,
  Server,
  Globe,
  Layers
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface DocumentationLibraryProps {
  onClose: () => void;
}

interface DocSection {
  id: string;
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
  items: DocItem[];
}

interface DocItem {
  id: string;
  title: string;
  description: string;
  type: 'guide' | 'tutorial' | 'reference' | 'faq' | 'api';
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  estimatedTime: string;
  content: string;
  codeExamples?: CodeExample[];
  prerequisites?: string[];
  expectedOutcomes?: string[];
  qaSteps?: QAStep[];
}

interface CodeExample {
  title: string;
  language: string;
  code: string;
  explanation: string;
}

interface QAStep {
  step: string;
  expectedResult: string;
  troubleshooting?: string;
}

export const DocumentationLibrary: React.FC<DocumentationLibraryProps> = ({ onClose }) => {
  const { toast } = useToast();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSection, setSelectedSection] = useState('getting-started');
  const [selectedDoc, setSelectedDoc] = useState<string | null>(null);
  const [bookmarkedDocs, setBookmarkedDocs] = useState<string[]>([]);

  // Comprehensive documentation sections
  const documentationSections: DocSection[] = [
    {
      id: 'getting-started',
      title: 'Getting Started',
      description: 'Quick start guides and basic setup',
      icon: Rocket,
      badge: 'Essential',
      items: [
        {
          id: 'quick-start',
          title: 'Quick Start Guide',
          description: 'Get up and running in 5 minutes',
          type: 'tutorial',
          difficulty: 'beginner',
          estimatedTime: '5 minutes',
          content: `# Quick Start Guide

## Overview
The IPS Security Center provides comprehensive security monitoring and penetration testing capabilities through an intuitive web interface.

## Prerequisites
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Network access to security services
- Basic understanding of cybersecurity concepts

## Step 1: Access the Platform
1. Navigate to the IPS Security Center URL
2. The dashboard will automatically load and begin health checks
3. Wait for service initialization (30-60 seconds)

## Step 2: Verify Service Status
1. Check the service status indicators in the header
2. Green indicators mean services are online and ready
3. Orange/Red indicators require attention

## Step 3: Run Your First Scan
1. Navigate to the "Services" section
2. Click "Start CVE Assessment" 
3. Monitor the progress bar and findings
4. Review results in the alerts section

## Step 4: Explore Features
- **Real-time Monitoring**: View live security events
- **Penetration Testing**: Launch automated security assessments  
- **Agent Management**: Configure and monitor security agents
- **Compliance**: Generate compliance reports

## Next Steps
- Read the [Architecture Overview](#architecture-overview)
- Complete the [Security Configuration Tutorial](#security-config)
- Explore [Advanced Features](#advanced-features)`,
          expectedOutcomes: [
            'Successfully access the IPS Security Center dashboard',
            'Verify all security services are operational',
            'Complete your first vulnerability assessment',
            'Understand the basic navigation and features'
          ],
          qaSteps: [
            {
              step: 'Load the main dashboard',
              expectedResult: 'Dashboard loads within 10 seconds, service status indicators appear',
              troubleshooting: 'If dashboard fails to load, check network connectivity and browser compatibility'
            },
            {
              step: 'Verify service health',
              expectedResult: 'All service indicators show green (healthy) status',
              troubleshooting: 'Orange/red status indicates service issues - check backend connectivity'
            },
            {
              step: 'Run vulnerability scan',
              expectedResult: 'Scan initiates and shows progress, findings appear in real-time',
              troubleshooting: 'If scan fails to start, verify target configuration and service availability'
            }
          ]
        },
        {
          id: 'architecture-overview',
          title: 'Architecture Overview',
          description: 'Understanding the platform architecture and components',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '15 minutes',
          content: `# Architecture Overview

## System Architecture

The IPS Security Center follows a microservices architecture with the following components:

### Frontend Layer
- **React Application**: Modern single-page application
- **Real-time WebSocket**: Live updates and notifications
- **Responsive Design**: Works on desktop and mobile devices

### Security Services Layer
- **Wazuh SIEM**: Security information and event management
- **OpenVAS/GVM**: Vulnerability assessment and management  
- **OWASP ZAP**: Web application security testing
- **SpiderFoot**: Open source intelligence gathering

### Integration Layer
- **Security API Gateway**: Unified API access to all services
- **Authentication Service**: User management and access control
- **Event Bus**: Real-time event distribution
- **Data Aggregation**: Centralized security data processing

### Data Layer
- **Time-series Database**: Security metrics and events
- **Document Store**: Vulnerability and scan results
- **Configuration Database**: System and user settings
- **Audit Logs**: Compliance and forensic data

## Component Interactions

\`\`\`mermaid
graph TD
    A[Frontend Dashboard] --> B[API Gateway]
    B --> C[Wazuh SIEM]
    B --> D[OpenVAS/GVM] 
    B --> E[OWASP ZAP]
    B --> F[SpiderFoot]
    C --> G[Event Bus]
    D --> G
    E --> G
    F --> G
    G --> H[WebSocket Server]
    H --> A
\`\`\`

## Security Model
- **Zero Trust Architecture**: All communications are encrypted and authenticated
- **Role-Based Access Control**: Granular permissions based on user roles
- **Audit Logging**: Complete trail of all security activities
- **Network Segmentation**: Services isolated in secure network zones`,
          prerequisites: ['Basic understanding of cybersecurity concepts', 'Familiarity with web applications'],
          expectedOutcomes: [
            'Understand the overall system architecture',
            'Know how different components interact',
            'Grasp the security model and data flow',
            'Identify integration points for custom tools'
          ]
        }
      ]
    },
    {
      id: 'security-features',
      title: 'Security Features',
      description: 'Comprehensive security testing and monitoring capabilities',
      icon: Shield,
      badge: 'Core',
      items: [
        {
          id: 'vulnerability-scanning',
          title: 'Vulnerability Scanning',
          description: 'Automated vulnerability assessment and management',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '20 minutes',
          content: `# Vulnerability Scanning Guide

## Overview
The vulnerability scanning module provides comprehensive security assessment capabilities using industry-standard tools and methodologies.

## Supported Scan Types

### 1. CVE Assessment
- **Purpose**: Identify known vulnerabilities in target systems
- **Coverage**: Network services, web applications, operating systems
- **Methodology**: NIST SP 800-115 compliant scanning

### 2. OWASP Web Application Testing
- **Purpose**: Test web applications for security weaknesses
- **Coverage**: OWASP Top 10 vulnerabilities and beyond
- **Tools**: ZAP, custom scanners, manual testing procedures

### 3. Network Penetration Testing
- **Purpose**: Assess network security posture
- **Coverage**: Port scanning, service enumeration, configuration analysis
- **Tools**: Nmap, custom scripts, network analyzers

## Step-by-Step Scanning Procedure

### Phase 1: Target Preparation
1. **Define Scope**
   - Identify target systems and networks
   - Establish scanning boundaries
   - Document authorized scan windows

2. **Configure Scan Parameters**
   - Select appropriate scan intensity
   - Choose vulnerability categories
   - Set scan scheduling and frequency

### Phase 2: Scan Execution
1. **Initiate Scan**
   \`\`\`bash
   # Example: Network vulnerability scan
   nmap -sV -sC --script vuln target.example.com
   
   # Web application scan
   zap-baseline.py -t https://target.example.com
   \`\`\`

2. **Monitor Progress**
   - Real-time scan status updates
   - Resource utilization monitoring  
   - Error handling and retry logic

### Phase 3: Results Analysis
1. **Vulnerability Classification**
   - CVSS scoring and risk assessment
   - False positive identification
   - Impact and exploitability analysis

2. **Report Generation**
   - Executive summary with risk metrics
   - Technical details for remediation
   - Compliance mapping (PCI, SOX, HIPAA)

## Expected Scan Results

### High-Risk Findings
- **Critical CVE vulnerabilities**: Require immediate attention
- **Authentication bypasses**: Direct security control failures
- **Code injection flaws**: SQL injection, command injection, etc.

### Medium-Risk Findings  
- **Information disclosure**: Version exposure, debug information
- **Configuration weaknesses**: Default passwords, weak crypto
- **Session management flaws**: Token weaknesses, fixation issues

### Low-Risk Findings
- **Informational exposures**: Banner grabbing, directory listings
- **Best practice violations**: Missing security headers
- **Performance issues**: Resource consumption, DoS potential

## QA Validation Steps

1. **Scan Initiation**
   - ✅ Scan starts within 30 seconds
   - ✅ Progress indicators update correctly
   - ✅ Target connectivity verified

2. **Scan Execution**
   - ✅ No false negatives for known vulnerabilities
   - ✅ Scan completes within expected timeframe
   - ✅ Resource usage stays within limits

3. **Results Accuracy**
   - ✅ CVSS scores match vulnerability databases
   - ✅ False positive rate < 5%
   - ✅ All critical findings verified manually`,
          codeExamples: [
            {
              title: 'Network Vulnerability Scan',
              language: 'bash',
              code: `# Comprehensive network vulnerability assessment
nmap -sS -sV -O --script vuln,safe 192.168.1.0/24

# Output interpretation:
# - Open ports and services identified
# - CVE vulnerabilities mapped to services  
# - Operating system fingerprinting results
# - Safe NSE scripts executed for additional checks`,
              explanation: 'This command performs a comprehensive network scan including service detection, OS fingerprinting, and vulnerability detection using Nmap NSE scripts.'
            },
            {
              title: 'Web Application Security Scan',
              language: 'python',
              code: `#!/usr/bin/env python3
import requests
from zapv2 import ZAPv2

# Initialize ZAP API client
zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080'})

# Target URL
target = 'https://example.com'

# Step 1: Spider the application
print(f'Spidering {target}')
scanid = zap.spider.scan(target)
while int(zap.spider.status(scanid)) < 100:
    print(f'Spider progress: {zap.spider.status(scanid)}%')
    time.sleep(2)

# Step 2: Active security scan
print('Starting active scan')
scanid = zap.ascan.scan(target)
while int(zap.ascan.status(scanid)) < 100:
    print(f'Scan progress: {zap.ascan.status(scanid)}%')
    time.sleep(5)

# Step 3: Generate report
alerts = zap.core.alerts(baseurl=target)
print(f'Found {len(alerts)} security issues')

for alert in alerts:
    print(f'{alert["risk"]} - {alert["alert"]} - {alert["url"]}')`,
              explanation: 'This Python script demonstrates automated web application security testing using the OWASP ZAP API, including crawling and active vulnerability scanning.'
            }
          ],
          qaSteps: [
            {
              step: 'Configure scan target and parameters',
              expectedResult: 'Target validates successfully, scan parameters accepted',
              troubleshooting: 'Check target reachability and parameter format validation'
            },
            {
              step: 'Execute vulnerability scan',
              expectedResult: 'Scan progresses normally, real-time updates visible',
              troubleshooting: 'Monitor for timeouts or connectivity issues'
            },
            {
              step: 'Analyze scan results',
              expectedResult: 'Vulnerabilities classified with CVSS scores, actionable recommendations provided',
              troubleshooting: 'Validate findings against known vulnerability databases'
            }
          ]
        },
        {
          id: 'agentic-pentest',
          title: 'AI-Powered Penetration Testing',
          description: 'Autonomous security assessment with AI decision-making',
          type: 'tutorial',
          difficulty: 'advanced',
          estimatedTime: '45 minutes',
          content: `# AI-Powered Penetration Testing

## Introduction
The Agentic Penetration Testing module combines artificial intelligence with traditional security testing methodologies to provide autonomous, intelligent security assessments.

## AI Models Supported
- **GPT-5 (2025-08-07)**: Latest OpenAI model with enhanced reasoning
- **Claude Sonnet 4**: Advanced analysis and decision-making
- **Perplexity**: Real-time threat intelligence integration

## Configuration Steps

### 1. AI Agent Setup
1. **Select AI Model**
   - Choose based on testing requirements
   - Consider context window size and reasoning capabilities
   - Configure temperature for precision vs creativity

2. **Configure System Prompt**
   \`\`\`
   You are an expert penetration tester with knowledge of:
   - OWASP Testing Methodology v4.2
   - NIST SP 800-115 Technical Guide
   - Kali Linux security tools
   - CVE database and exploitation techniques
   \`\`\`

3. **Set Decision Parameters**
   - Risk tolerance level
   - Confirmation requirements for destructive actions
   - Command blacklisting for safety

### 2. Target Configuration
1. **Define Target Scope**
   - Primary target (IP/URL/domain)
   - In-scope and out-of-scope systems
   - Authorized testing windows

2. **Authentication Setup**
   - Credential information if applicable
   - API keys for authenticated testing
   - Session management requirements

### 3. Tool Selection
Enable appropriate security tools:
- **Nmap**: Network discovery and port scanning
- **SQLMap**: SQL injection testing
- **Nikto**: Web vulnerability scanning
- **Amass**: Asset discovery and enumeration

## Autonomous Testing Flow

### Phase 1: Reconnaissance
The AI agent begins with passive information gathering:

1. **OSINT Collection**
   - Subdomain enumeration
   - Email and personnel harvesting
   - Technology stack identification

2. **Network Discovery**
   - Host enumeration
   - Service detection
   - Network topology mapping

### Phase 2: Vulnerability Assessment
AI-driven vulnerability identification:

1. **Automated Scanning**
   - Port and service enumeration
   - Version detection and CVE correlation
   - Configuration analysis

2. **Intelligent Analysis**
   - Risk-based vulnerability prioritization
   - Attack surface mapping
   - Exploitation path planning

### Phase 3: Exploitation
Controlled exploitation with AI decision-making:

1. **Exploit Selection**
   - AI chooses appropriate techniques
   - Risk assessment for each attempt
   - Human confirmation for high-risk actions

2. **Chain Exploitation**
   - Multi-step attack sequences
   - Privilege escalation attempts
   - Lateral movement planning

## Expected Outcomes

### Automated Discovery
- **Asset Inventory**: Complete enumeration of target infrastructure
- **Service Mapping**: Detailed service and version information
- **Vulnerability Database**: Prioritized list with CVSS scores

### Intelligence Analysis
- **Risk Assessment**: Business impact analysis for each finding
- **Exploitation Guidance**: Step-by-step attack procedures
- **Remediation Plans**: Prioritized fix recommendations

### Compliance Reporting
- **Executive Summary**: High-level risk overview
- **Technical Details**: Detailed findings with evidence
- **Compliance Mapping**: Alignment with security frameworks

## Quality Assurance

### AI Decision Validation
1. **Command Safety Checks**
   - Blacklisted command detection
   - Destructive action confirmation
   - Scope boundary enforcement

2. **Result Verification**
   - False positive identification
   - Manual validation prompts
   - Confidence scoring

### Performance Metrics
- **Coverage**: Percentage of attack surface tested
- **Accuracy**: False positive/negative rates
- **Efficiency**: Time to identify critical vulnerabilities

## Troubleshooting

### Common Issues
1. **AI Model Timeouts**
   - Reduce context window size
   - Simplify system prompts
   - Check API rate limits

2. **Tool Execution Failures**
   - Verify tool availability
   - Check network connectivity
   - Validate target accessibility

3. **Unexpected Results**
   - Review AI reasoning logs
   - Validate tool configurations
   - Check target environment changes`,
          prerequisites: [
            'Advanced penetration testing knowledge',
            'Understanding of AI/LLM capabilities',
            'API key for chosen AI model',
            'Proper authorization for testing'
          ],
          expectedOutcomes: [
            'Deploy autonomous AI penetration testing agent',
            'Configure intelligent decision-making parameters',
            'Execute full-stack security assessments',
            'Generate comprehensive security reports with AI insights'
          ],
          codeExamples: [
            {
              title: 'AI Agent Configuration',
              language: 'typescript',
              code: `const aiConfig: AIAgentConfig = {
  model: 'gpt-5-2025-08-07',
  temperature: 0.2, // Low for precise security analysis
  maxTokens: 4000,
  systemPrompt: \`Expert penetration tester with OWASP methodology knowledge...\`,
  decisionMaking: {
    riskTolerance: 'moderate',
    confirmationRequired: true,
    blacklistCommands: ['rm -rf', 'dd if=', 'format'],
    whitelistTargets: ['10.0.0.0/8', '192.168.0.0/16']
  },
  capabilities: {
    commandGeneration: true,
    outputAnalysis: true,
    exploitSelection: true,
    reportGeneration: true
  }
};`,
              explanation: 'This configuration sets up an AI agent for autonomous penetration testing with appropriate safety controls and decision-making parameters.'
            }
          ]
        }
      ]
    },
    {
      id: 'integration-apis',
      title: 'Integration & APIs',
      description: 'API documentation and integration guides',
      icon: Code,
      items: [
        {
          id: 'rest-api',
          title: 'REST API Reference',
          description: 'Complete API documentation with examples',
          type: 'reference',
          difficulty: 'intermediate',
          estimatedTime: '30 minutes',
          content: `# REST API Reference

## Base URL
\`\`\`
https://api.ips-security-center.com/v1
\`\`\`

## Authentication
All API requests require authentication using API keys:

\`\`\`http
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json
\`\`\`

## Security Services

### GET /services/health
Get health status of all security services.

**Response:**
\`\`\`json
{
  "success": true,
  "data": {
    "wazuh": {
      "status": "healthy",
      "responseTime": 45,
      "version": "4.7.3"
    },
    "gvm": {
      "status": "healthy", 
      "responseTime": 123,
      "version": "22.4.1"
    }
  }
}
\`\`\`

### POST /scans/vulnerability
Start a new vulnerability scan.

**Request:**
\`\`\`json
{
  "target": "192.168.1.100",
  "scanType": "comprehensive",
  "options": {
    "portRange": "1-65535",
    "intensity": "normal",
    "scripts": ["vuln", "safe"]
  }
}
\`\`\`

**Response:**
\`\`\`json
{
  "success": true,
  "data": {
    "scanId": "scan_12345",
    "status": "initiated",
    "estimatedDuration": "15 minutes"
  }
}
\`\`\`

### GET /scans/{scanId}/results
Retrieve scan results.

**Response:**
\`\`\`json
{
  "success": true,
  "data": {
    "scanId": "scan_12345",
    "status": "completed",
    "vulnerabilities": [
      {
        "id": "vuln_001",
        "severity": "high",
        "title": "SQL Injection in login form",
        "cvss": 8.1,
        "description": "Authentication bypass via SQL injection"
      }
    ]
  }
}
\`\`\`

## WebSocket Events

### Connection
\`\`\`javascript
const ws = new WebSocket('wss://api.ips-security-center.com/ws');
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'authenticate',
    token: 'YOUR_API_KEY'
  }));
};
\`\`\`

### Real-time Events
\`\`\`javascript
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  switch(data.type) {
    case 'security_alert':
      console.log('New security alert:', data.alert);
      break;
    case 'scan_progress':
      console.log('Scan progress:', data.progress);
      break;
  }
};
\`\`\`

## Rate Limits
- 100 requests per minute for scan operations
- 1000 requests per minute for data retrieval
- WebSocket connections: 10 concurrent per API key

## Error Codes
- 400: Bad Request - Invalid parameters
- 401: Unauthorized - Invalid or missing API key
- 403: Forbidden - Insufficient permissions
- 429: Rate Limited - Too many requests
- 500: Internal Server Error - System issue`,
          codeExamples: [
            {
              title: 'Python API Client',
              language: 'python',
              code: `import requests
import json

class IPSSecurityAPI:
    def __init__(self, api_key, base_url="https://api.ips-security-center.com/v1"):
        self.api_key = api_key
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        })
    
    def get_service_health(self):
        """Get health status of all services"""
        response = self.session.get(f"{self.base_url}/services/health")
        return response.json()
    
    def start_vulnerability_scan(self, target, scan_type="comprehensive"):
        """Start a new vulnerability scan"""
        payload = {
            "target": target,
            "scanType": scan_type,
            "options": {
                "portRange": "1-65535",
                "intensity": "normal"
            }
        }
        response = self.session.post(f"{self.base_url}/scans/vulnerability", json=payload)
        return response.json()
    
    def get_scan_results(self, scan_id):
        """Get results for a specific scan"""
        response = self.session.get(f"{self.base_url}/scans/{scan_id}/results")
        return response.json()

# Usage example
api = IPSSecurityAPI("your_api_key_here")
health = api.get_service_health()
print(f"Services status: {health}")`,
              explanation: 'Python client library for interacting with the IPS Security Center API, providing easy access to all security services and scan operations.'
            }
          ]
        }
      ]
    },
    {
      id: 'compliance',
      title: 'Compliance & Reporting',
      description: 'Regulatory compliance and audit reporting',
      icon: FileText,
      items: [
        {
          id: 'compliance-frameworks',
          title: 'Supported Compliance Frameworks',
          description: 'Complete guide to compliance reporting and audit preparation',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '25 minutes',
          content: `# Compliance Frameworks

## Supported Standards

### SOC 2 Type II
**System and Organization Controls**

The platform supports SOC 2 compliance through:
- **Security**: Data protection and access controls
- **Availability**: System uptime and performance monitoring
- **Processing Integrity**: Accurate and complete data processing
- **Confidentiality**: Information protection mechanisms
- **Privacy**: Personal information handling procedures

#### Key Controls Implemented:
1. **CC6.1** - Logical and physical access controls
2. **CC6.2** - Authentication and authorization
3. **CC6.3** - System access removal procedures
4. **CC7.1** - Threat detection and monitoring
5. **CC7.2** - Security incident response

#### Evidence Collection:
- Automated security log collection
- Access control audit trails
- Vulnerability assessment reports
- Security awareness training records

### ISO 27001:2013
**Information Security Management System**

#### Control Domains Covered:
- **A.5** - Information security policies
- **A.6** - Organization of information security
- **A.8** - Asset management
- **A.9** - Access control
- **A.10** - Cryptography
- **A.12** - Operations security
- **A.13** - Communications security
- **A.14** - System acquisition and maintenance
- **A.16** - Information security incident management

#### Implementation Evidence:
\`\`\`
Controls Implementation Matrix:
├── A.12.6.1 - Vulnerability Management ✅
├── A.12.6.2 - Software Installation ✅  
├── A.13.1.1 - Network Controls ✅
├── A.14.2.1 - Secure Development ✅
└── A.16.1.1 - Incident Response ✅
\`\`\`

### PCI DSS v4.0
**Payment Card Industry Data Security Standard**

#### Requirements Mapping:
1. **Build and Maintain Secure Networks**
   - Firewall configuration management
   - Network segmentation validation
   - Secure communication protocols

2. **Protect Cardholder Data**
   - Data encryption at rest and in transit
   - Strong cryptography implementation
   - Secure key management

3. **Maintain Vulnerability Management**
   - Regular vulnerability assessments
   - Security patch management
   - Anti-virus/anti-malware programs

4. **Implement Strong Access Controls**
   - Role-based access control
   - Multi-factor authentication
   - Regular access reviews

#### Automated Compliance Checks:
\`\`\`bash
# PCI DSS Requirement 11.2 - Quarterly vulnerability scans
./compliance_scanner.sh --framework pci_dss --requirement 11.2

# Expected output:
✅ Quarterly vulnerability scan completed
✅ All critical vulnerabilities addressed
✅ ASV scan results documented
\`\`\`

### NIST Cybersecurity Framework
**Cybersecurity Framework v1.1**

#### Core Functions:
1. **Identify (ID)**
   - Asset Management (ID.AM)
   - Business Environment (ID.BE)  
   - Governance (ID.GV)
   - Risk Assessment (ID.RA)

2. **Protect (PR)**
   - Identity Management (PR.AC)
   - Awareness Training (PR.AT)
   - Data Security (PR.DS)
   - Information Protection (PR.IP)

3. **Detect (DE)**
   - Anomalies and Events (DE.AE)
   - Security Monitoring (DE.CM)
   - Detection Processes (DE.DP)

4. **Respond (RS)**
   - Response Planning (RS.RP)
   - Communications (RS.CO)
   - Analysis (RS.AN)
   - Mitigation (RS.MI)

5. **Recover (RC)**
   - Recovery Planning (RC.RP)
   - Improvements (RC.IM)
   - Communications (RC.CO)

## Report Generation

### Executive Summary Report
\`\`\`json
{
  "reportType": "executive_summary",
  "period": "Q1 2024",
  "complianceScore": 94,
  "keyFindings": {
    "critical": 0,
    "high": 2,
    "medium": 15,
    "low": 42
  },
  "recommendations": [
    "Implement multi-factor authentication",
    "Update vulnerability management procedures",
    "Enhance security awareness training"
  ]
}
\`\`\`

### Technical Compliance Report
Detailed technical evidence for auditors:
- Security control implementation status
- Vulnerability assessment results
- Penetration testing findings
- Risk assessment documentation
- Incident response logs

### Audit Trail Documentation
- All security events with timestamps
- Configuration changes with approval
- Access control modifications
- Security policy updates
- Training completion records

## QA Validation for Compliance

### Pre-Audit Checklist
1. **Documentation Review**
   - [ ] All policies updated and approved
   - [ ] Risk assessments completed
   - [ ] Security controls documented
   - [ ] Training records current

2. **Technical Validation**
   - [ ] Vulnerability scans completed
   - [ ] Penetration tests executed
   - [ ] Security configurations verified
   - [ ] Backup and recovery tested

3. **Process Verification**
   - [ ] Incident response procedures tested
   - [ ] Change management process validated
   - [ ] Access control reviews completed
   - [ ] Vendor security assessments current

### Expected Audit Outcomes
- **Clean Audit Opinion**: No material deficiencies
- **Control Effectiveness**: All controls operating effectively
- **Compliance Rating**: 95%+ compliance score
- **Risk Mitigation**: All high-risk findings addressed`,
          qaSteps: [
            {
              step: 'Generate compliance report',
              expectedResult: 'Report includes all required evidence and control implementations',
              troubleshooting: 'Verify data collection periods and control mapping accuracy'
            },
            {
              step: 'Validate control effectiveness',
              expectedResult: 'All controls show "Operating Effectively" status',
              troubleshooting: 'Review control testing procedures and evidence quality'
            },
            {
              step: 'Prepare for audit',
              expectedResult: 'All documentation organized and accessible for auditors',
              troubleshooting: 'Ensure evidence is complete and properly formatted'
            }
          ]
        }
      ]
    },
    {
      id: 'troubleshooting',
      title: 'Troubleshooting',
      description: 'Common issues, solutions, and debugging guides',
      icon: Wrench,
      items: [
        {
          id: 'common-issues',
          title: 'Common Issues & Solutions',
          description: 'Frequently encountered problems and their resolutions',
          type: 'faq',
          difficulty: 'beginner',
          estimatedTime: '10 minutes',
          content: `# Common Issues & Solutions

## Service Connection Issues

### Problem: "Service Unavailable" Errors
**Symptoms:**
- Red status indicators in dashboard
- "NetworkError when attempting to fetch resource" messages
- WebSocket connection failures

**Solutions:**
1. **Check Backend Services**
   \`\`\`bash
   # Verify service status
   curl -I http://localhost:55000/health  # Wazuh
   curl -I http://localhost:9392/health   # GVM
   curl -I http://localhost:8080/health   # ZAP
   \`\`\`

2. **Verify Network Connectivity**
   \`\`\`bash
   # Test network connectivity
   ping wazuh-manager.local
   telnet gvm-scanner.local 9392
   nmap -p 8080,55000,9392,5001 localhost
   \`\`\`

3. **Check Configuration**
   - Verify service URLs in configuration
   - Validate API keys and credentials
   - Check firewall and network policies

### Problem: Authentication Failures
**Symptoms:**
- 401 Unauthorized responses
- "Invalid API key" messages
- Login redirects or failures

**Solutions:**
1. **Validate Credentials**
   \`\`\`bash
   # Test Wazuh authentication
   curl -u wazuh:wazuh http://localhost:55000/security/user/authenticate
   
   # Verify API keys
   echo $WAZUH_API_KEY | base64 -d
   \`\`\`

2. **Reset API Keys**
   - Generate new API keys in service administration
   - Update configuration with new credentials
   - Restart services to pick up changes

## Scan and Assessment Issues

### Problem: Scans Fail to Start or Complete
**Symptoms:**
- Scan progress stuck at 0%
- "Scan failed after multiple attempts" errors
- Timeout errors during scanning

**Solutions:**
1. **Check Target Accessibility**
   \`\`\`bash
   # Verify target is reachable
   ping target.example.com
   nmap -Pn target.example.com
   curl -I http://target.example.com
   \`\`\`

2. **Validate Scan Parameters**
   - Ensure target format is correct (IP/URL)
   - Check scan scope and exclusions
   - Verify scan intensity settings

3. **Monitor Resource Usage**
   \`\`\`bash
   # Check system resources
   top -p $(pgrep nmap)
   iostat -x 1
   df -h /tmp
   \`\`\`

### Problem: High False Positive Rates
**Symptoms:**
- Vulnerability reports with invalid findings
- "Unable to reproduce" results
- Inconsistent scan results

**Solutions:**
1. **Manual Validation**
   - Verify reported vulnerabilities manually
   - Check version information accuracy
   - Test exploit scenarios

2. **Tune Detection Rules**
   - Adjust scanner sensitivity settings
   - Update vulnerability signatures
   - Configure custom detection rules

## Performance Issues

### Problem: Slow Dashboard Loading
**Symptoms:**
- Dashboard takes >10 seconds to load
- Unresponsive UI elements
- Browser console errors

**Solutions:**
1. **Clear Browser Cache**
   \`\`\`javascript
   // Clear localStorage
   localStorage.clear();
   
   // Clear sessionStorage
   sessionStorage.clear();
   \`\`\`

2. **Check Network Performance**
   \`\`\`bash
   # Test API response times
   curl -w "@curl-format.txt" -o /dev/null -s http://api.ips-security.com/health
   \`\`\`

3. **Optimize Data Loading**
   - Reduce real-time update frequency
   - Implement data pagination
   - Use lazy loading for large datasets

## Data and Reporting Issues

### Problem: Missing or Incomplete Reports
**Symptoms:**
- Empty report sections
- Data not appearing in dashboards
- Export functions not working

**Solutions:**
1. **Verify Data Collection**
   \`\`\`sql
   -- Check database connectivity
   SELECT COUNT(*) FROM security_events WHERE date > NOW() - INTERVAL 1 DAY;
   
   -- Verify data integrity
   SELECT service, COUNT(*) FROM scan_results GROUP BY service;
   \`\`\`

2. **Check Report Generation**
   - Verify report templates exist
   - Check file permissions for exports
   - Validate data format requirements

## Advanced Troubleshooting

### Enable Debug Logging
\`\`\`javascript
// Enable debug mode in browser console
localStorage.setItem('debug', 'true');
localStorage.setItem('logLevel', 'debug');

// Reload page to activate debug logging
window.location.reload();
\`\`\`

### Collect Diagnostic Information
\`\`\`bash
#!/bin/bash
# System diagnostic script
echo "=== System Information ==="
uname -a
cat /etc/os-release

echo "=== Service Status ==="
systemctl status wazuh-manager
systemctl status openvas-scanner

echo "=== Network Configuration ==="
ip addr show
ss -tulpn | grep -E ':(8080|55000|9392|5001)'

echo "=== Resource Usage ==="
free -h
df -h
top -b -n1 | head -20
\`\`\`

### Log File Locations
\`\`\`
Application Logs:
├── Frontend: Browser Developer Tools → Console
├── Wazuh: /var/ossec/logs/api.log
├── GVM: /var/log/gvm/gvmd.log
├── ZAP: ~/.ZAP/zap.log
└── System: /var/log/syslog
\`\`\`

## Getting Additional Help

### Before Contacting Support
1. **Check System Requirements**
   - Browser compatibility
   - Network requirements
   - Resource specifications

2. **Review Documentation**
   - Configuration guides
   - API documentation
   - Known issues list

3. **Gather Information**
   - Error messages and screenshots
   - System configuration details
   - Steps to reproduce the issue

### Support Channels
- **Documentation**: Internal knowledge base
- **Community**: Security forums and discussions  
- **Technical Support**: Priority support for critical issues
- **Professional Services**: Custom implementation assistance`,
          qaSteps: [
            {
              step: 'Identify the problem category',
              expectedResult: 'Issue classified as service, scan, performance, or data problem',
              troubleshooting: 'Use diagnostic scripts to gather system information'
            },
            {
              step: 'Apply appropriate solution',
              expectedResult: 'Issue resolved using documented procedures',
              troubleshooting: 'If solution fails, escalate to next troubleshooting level'
            },
            {
              step: 'Verify resolution',
              expectedResult: 'System returns to normal operation, no recurring issues',
              troubleshooting: 'Monitor system for 24 hours to ensure stability'
            }
          ]
        }
      ]
    }
  ];

  // Filter documentation based on search
  const filteredSections = searchQuery
    ? documentationSections.map(section => ({
        ...section,
        items: section.items.filter(item =>
          item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
          item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
          item.content.toLowerCase().includes(searchQuery.toLowerCase())
        )
      })).filter(section => section.items.length > 0)
    : documentationSections;

  // Get current documentation item
  const getCurrentDoc = () => {
    if (!selectedDoc) return null;
    for (const section of documentationSections) {
      const doc = section.items.find(item => item.id === selectedDoc);
      if (doc) return doc;
    }
    return null;
  };

  const currentDoc = getCurrentDoc();

  // Copy code to clipboard
  const copyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    toast({
      title: "Code Copied",
      description: "Code snippet copied to clipboard"
    });
  };

  // Toggle bookmark
  const toggleBookmark = (docId: string) => {
    setBookmarkedDocs(prev => 
      prev.includes(docId) 
        ? prev.filter(id => id !== docId)
        : [...prev, docId]
    );
  };

  return (
    <div className="fixed inset-0 bg-background/95 backdrop-blur-sm z-50 flex">
      {/* Sidebar Navigation */}
      <div className="w-80 border-r border-border bg-card/50 flex flex-col">
        <div className="p-6 border-b border-border">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Book className="w-5 h-5 text-primary" />
              <h2 className="text-lg font-semibold">Documentation</h2>
            </div>
            <Button variant="ghost" size="sm" onClick={onClose}>
              ×
            </Button>
          </div>
          
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search documentation..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>
        </div>

        <ScrollArea className="flex-1 p-4">
          {filteredSections.map((section) => (
            <div key={section.id} className="mb-6">
              <div
                className={`flex items-center gap-2 p-3 rounded-lg cursor-pointer transition-colors ${
                  selectedSection === section.id 
                    ? 'bg-primary/10 text-primary' 
                    : 'hover:bg-muted/50'
                }`}
                onClick={() => setSelectedSection(section.id)}
              >
                <section.icon className="w-4 h-4" />
                <span className="font-medium">{section.title}</span>
                {section.badge && (
                  <Badge variant="secondary" className="text-xs">
                    {section.badge}
                  </Badge>
                )}
              </div>
              
              {selectedSection === section.id && (
                <div className="mt-2 ml-6 space-y-1">
                  {section.items.map((item) => (
                    <div
                      key={item.id}
                      className={`flex items-center justify-between p-2 rounded cursor-pointer transition-colors ${
                        selectedDoc === item.id 
                          ? 'bg-primary/5 text-primary' 
                          : 'hover:bg-muted/30'
                      }`}
                      onClick={() => setSelectedDoc(item.id)}
                    >
                      <div className="flex items-center gap-2 flex-1">
                        <div className="w-2 h-2 rounded-full bg-current opacity-50" />
                        <span className="text-sm">{item.title}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <Badge variant="outline" className="text-xs">
                          {item.difficulty}
                        </Badge>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="w-6 h-6 p-0"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleBookmark(item.id);
                          }}
                        >
                          <Star 
                            className={`w-3 h-3 ${
                              bookmarkedDocs.includes(item.id) 
                                ? 'fill-current text-yellow-500' 
                                : 'text-muted-foreground'
                            }`} 
                          />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </ScrollArea>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col">
        {currentDoc ? (
          <>
            {/* Document Header */}
            <div className="border-b border-border bg-card/30 p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h1 className="text-2xl font-bold mb-2">{currentDoc.title}</h1>
                  <p className="text-muted-foreground mb-4">{currentDoc.description}</p>
                  
                  <div className="flex items-center gap-4 text-sm text-muted-foreground">
                    <div className="flex items-center gap-1">
                      <Clock className="w-4 h-4" />
                      {currentDoc.estimatedTime}
                    </div>
                    <div className="flex items-center gap-1">
                      <BarChart3 className="w-4 h-4" />
                      {currentDoc.difficulty}
                    </div>
                    <div className="flex items-center gap-1">
                      <FileText className="w-4 h-4" />
                      {currentDoc.type}
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm">
                    <Download className="w-4 h-4 mr-2" />
                    Export PDF
                  </Button>
                  <Button 
                    variant="ghost" 
                    size="sm"
                    onClick={() => toggleBookmark(currentDoc.id)}
                  >
                    <Star 
                      className={`w-4 h-4 ${
                        bookmarkedDocs.includes(currentDoc.id) 
                          ? 'fill-current text-yellow-500' 
                          : ''
                      }`} 
                    />
                  </Button>
                </div>
              </div>

              {/* Prerequisites */}
              {currentDoc.prerequisites && currentDoc.prerequisites.length > 0 && (
                <Alert className="mb-4">
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Prerequisites:</strong> {currentDoc.prerequisites.join(', ')}
                  </AlertDescription>
                </Alert>
              )}

              {/* Expected Outcomes */}
              {currentDoc.expectedOutcomes && (
                <div className="bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
                  <h4 className="font-semibold text-green-800 dark:text-green-200 mb-2 flex items-center gap-2">
                    <CheckCircle className="w-4 h-4" />
                    Expected Outcomes
                  </h4>
                  <ul className="space-y-1 text-green-700 dark:text-green-300">
                    {currentDoc.expectedOutcomes.map((outcome, index) => (
                      <li key={index} className="flex items-start gap-2">
                        <ArrowRight className="w-4 h-4 mt-0.5 flex-shrink-0" />
                        {outcome}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Document Content */}
            <ScrollArea className="flex-1 p-6">
              <div className="prose prose-slate dark:prose-invert max-w-none">
                {/* Main Content */}
                <div className="whitespace-pre-wrap font-mono text-sm leading-relaxed">
                  {currentDoc.content}
                </div>

                {/* Code Examples */}
                {currentDoc.codeExamples && currentDoc.codeExamples.length > 0 && (
                  <div className="mt-8">
                    <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                      <Code className="w-5 h-5" />
                      Code Examples
                    </h3>
                    {currentDoc.codeExamples.map((example, index) => (
                      <Card key={index} className="mb-6">
                        <CardHeader>
                          <div className="flex items-center justify-between">
                            <CardTitle className="text-base">{example.title}</CardTitle>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyCode(example.code)}
                            >
                              <Copy className="w-4 h-4" />
                            </Button>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <pre className="bg-muted/50 p-4 rounded-lg overflow-x-auto text-sm">
                            <code>{example.code}</code>
                          </pre>
                          <p className="mt-3 text-sm text-muted-foreground">
                            {example.explanation}
                          </p>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}

                {/* QA Steps */}
                {currentDoc.qaSteps && currentDoc.qaSteps.length > 0 && (
                  <div className="mt-8">
                    <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                      <CheckCircle className="w-5 h-5" />
                      QA Validation Steps
                    </h3>
                    {currentDoc.qaSteps.map((step, index) => (
                      <Card key={index} className="mb-4">
                        <CardContent className="p-4">
                          <div className="flex items-start gap-3">
                            <Badge variant="outline" className="mt-1">
                              {index + 1}
                            </Badge>
                            <div className="flex-1">
                              <h4 className="font-medium mb-2">{step.step}</h4>
                              <div className="bg-green-50 dark:bg-green-950/20 border-l-4 border-green-400 p-3 mb-2">
                                <p className="text-sm text-green-800 dark:text-green-200">
                                  <strong>Expected Result:</strong> {step.expectedResult}
                                </p>
                              </div>
                              {step.troubleshooting && (
                                <div className="bg-yellow-50 dark:bg-yellow-950/20 border-l-4 border-yellow-400 p-3">
                                  <p className="text-sm text-yellow-800 dark:text-yellow-200">
                                    <strong>Troubleshooting:</strong> {step.troubleshooting}
                                  </p>
                                </div>
                              )}
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </div>
            </ScrollArea>
          </>
        ) : (
          /* Documentation Overview */
          <div className="flex-1 p-6">
            <div className="max-w-4xl mx-auto">
              <div className="text-center mb-8">
                <h1 className="text-3xl font-bold mb-4">IPS Security Center Documentation</h1>
                <p className="text-lg text-muted-foreground">
                  Comprehensive guides, tutorials, and references for the complete security platform
                </p>
              </div>

              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                {documentationSections.map((section) => (
                  <Card 
                    key={section.id}
                    className="cursor-pointer hover:shadow-lg transition-shadow duration-200 glow-hover"
                    onClick={() => setSelectedSection(section.id)}
                  >
                    <CardHeader>
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-primary/10">
                          <section.icon className="w-6 h-6 text-primary" />
                        </div>
                        <div>
                          <CardTitle className="text-lg">{section.title}</CardTitle>
                          {section.badge && (
                            <Badge variant="secondary" className="mt-1">
                              {section.badge}
                            </Badge>
                          )}
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <p className="text-muted-foreground mb-4">{section.description}</p>
                      <div className="flex items-center justify-between text-sm text-muted-foreground">
                        <span>{section.items.length} articles</span>
                        <ChevronRight className="w-4 h-4" />
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>

              {/* Quick Links */}
              <div className="mt-12">
                <h2 className="text-xl font-semibold mb-6">Quick Start</h2>
                <div className="grid md:grid-cols-2 gap-4">
                  <Card className="cursor-pointer hover:shadow-md transition-shadow">
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Play className="w-5 h-5 text-primary" />
                        <div>
                          <h3 className="font-medium">5-Minute Setup</h3>
                          <p className="text-sm text-muted-foreground">Get started with basic configuration</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="cursor-pointer hover:shadow-md transition-shadow">
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Code className="w-5 h-5 text-primary" />
                        <div>
                          <h3 className="font-medium">API Reference</h3>
                          <p className="text-sm text-muted-foreground">Complete API documentation</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};