import React, { useState } from 'react';
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle 
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import {
  Search,
  BookOpen,
  Code,
  AlertTriangle,
  Target,
  Rocket,
  Shield,
  Settings,
  Database,
  Globe,
  Lock,
  Eye,
  Brain,
  CheckCircle,
  Clock,
  Star,
  Download,
  ExternalLink,
  Copy,
  Bookmark,
  BookmarkCheck
} from 'lucide-react';

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
  troubleshootingTips?: string[];
  tags?: string[];
  lastUpdated?: string;
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

## Step 2: Service Verification
The platform will automatically check:
- **Wazuh SIEM**: Security event monitoring
- **OpenVAS/GVM**: Vulnerability assessment
- **OWASP ZAP**: Web application security testing
- **SpiderFoot**: OSINT intelligence gathering

## Step 3: Dashboard Overview
Key sections available:
- **Real-time Monitoring**: Live security events and alerts
- **Vulnerability Management**: Scan results and remediation
- **Penetration Testing**: Automated and manual testing tools
- **Intelligence Gathering**: OSINT and threat intelligence

## Next Steps
- Review the System Architecture guide
- Configure your first security scan
- Set up monitoring and alerting preferences`,
          prerequisites: ['Modern web browser', 'Network connectivity'],
          expectedOutcomes: [
            'Successfully access the platform',
            'Understand the main interface components',
            'Verify all services are operational'
          ]
        },
        {
          id: 'architecture-overview',
          title: 'System Architecture Overview',
          description: 'Understanding the platform architecture and components',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '15 minutes',
          content: `# System Architecture Overview

## High-Level Architecture

The IPS Security Center follows a microservices architecture with clear separation of concerns:

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
      id: 'osint-mastery',
      title: 'OSINT Mastery',
      description: 'Open Source Intelligence gathering techniques and methodologies',
      icon: Search,
      badge: 'Updated 2024',
      items: [
        {
          id: 'osint-methodology',
          title: 'OSINT Methodology & Best Practices',
          description: 'Comprehensive guide to professional OSINT investigation techniques',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '45 minutes',
          content: `# OSINT Methodology & Best Practices 2024

## Intelligence Collection Framework

### Phase 1: Planning & Direction
- **Define Objectives**: Clear intelligence requirements
- **Scope Definition**: Boundaries and limitations
- **Legal Compliance**: Ensure all activities are legal and ethical
- **Resource Allocation**: Tools, time, and personnel

### Phase 2: Collection
- **Passive Collection**: No direct interaction with targets
- **Active Collection**: Controlled interaction when necessary
- **Multi-source Verification**: Cross-reference information
- **Chain of Custody**: Maintain evidence integrity

### Phase 3: Processing & Analysis
- **Data Normalization**: Standardize collected information
- **Correlation Analysis**: Identify patterns and connections
- **Confidence Assessment**: Rate reliability of sources
- **Timeline Construction**: Chronological event mapping

### Phase 4: Dissemination
- **Report Generation**: Professional intelligence products
- **Stakeholder Communication**: Appropriate audience targeting
- **Secure Distribution**: Protect sensitive information
- **Feedback Collection**: Improve future operations

## Advanced OSINT Techniques

### Social Media Intelligence (SOCMINT)
\`\`\`bash
# Example: Twitter Intelligence Gathering
# Tools: TweetDeck, Social-Searcher, Twint
python3 -m twint -u target_username --limit 100 --csv
\`\`\`

### Domain Intelligence (DOMINT)
\`\`\`bash
# Subdomain enumeration
subfinder -d target.com | httprobe | tee live_subdomains.txt

# DNS reconnaissance
dig +trace target.com
nslookup -type=MX target.com
\`\`\`

### Image Intelligence (IMINT)
\`\`\`python
# Metadata extraction
from PIL import Image
from PIL.ExifTags import TAGS

def extract_metadata(image_path):
    image = Image.open(image_path)
    exifdata = image.getexif()
    
    for tag_id in exifdata:
        tag = TAGS.get(tag_id, tag_id)
        data = exifdata.get(tag_id)
        print(f"{tag}: {data}")
\`\`\`

## Legal & Ethical Considerations

### Compliance Framework
- **GDPR Compliance**: Data protection regulations
- **Terms of Service**: Respect platform policies
- **Attribution**: Proper source citation
- **Privacy Protection**: Minimize personal data exposure

### Operational Security (OPSEC)
- **VPN Usage**: Protect investigator identity
- **Sock Puppet Accounts**: Maintain cover identities
- **Data Segregation**: Isolate investigation data
- **Communication Security**: Encrypted channels

## Quality Assurance Checklist

### Source Verification
- [ ] Primary source identified
- [ ] Publication date verified
- [ ] Author credentials checked
- [ ] Cross-referenced with other sources

### Information Reliability
- [ ] Source credibility assessed
- [ ] Information freshness evaluated
- [ ] Potential bias identified
- [ ] Context considered

### Documentation Standards
- [ ] All sources documented
- [ ] Timestamps recorded
- [ ] Screenshots captured
- [ ] Chain of custody maintained`,
          prerequisites: ['Basic OSINT knowledge', 'Understanding of legal frameworks'],
          expectedOutcomes: [
            'Master professional OSINT methodology',
            'Implement quality assurance processes',
            'Ensure legal and ethical compliance',
            'Produce high-quality intelligence reports'
          ],
          qaSteps: [
            {
              step: 'Source Verification Check',
              expectedResult: 'All sources verified and documented',
              troubleshooting: 'If source cannot be verified, mark as unconfirmed and seek additional sources'
            },
            {
              step: 'Legal Compliance Review',
              expectedResult: 'All activities comply with applicable laws',
              troubleshooting: 'Consult legal counsel if uncertain about compliance'
            }
          ]
        }
      ]
    },
    {
      id: 'incident-response',
      title: 'Incident Response',
      description: 'Comprehensive incident response and digital forensics procedures',
      icon: AlertTriangle,
      badge: 'NIST Compliant',
      items: [
        {
          id: 'ir-playbook',
          title: 'Incident Response Playbook',
          description: 'Step-by-step procedures for cybersecurity incident management',
          type: 'guide',
          difficulty: 'advanced',
          estimatedTime: '60 minutes',
          content: `# Incident Response Playbook (NIST CSF Aligned)

## Phase 1: Preparation

### Team Structure
- **Incident Commander**: Overall response coordination
- **Security Analyst**: Technical investigation lead
- **Communications Lead**: Stakeholder communications
- **Legal Counsel**: Compliance and legal guidance

### Tools & Resources
\`\`\`bash
# Essential IR toolkit
sudo apt install volatility3 sleuthkit autopsy
pip3 install yara-python requests-toolbelt
\`\`\`

### Documentation Templates
- Incident classification matrix
- Evidence collection forms
- Communication templates
- Post-incident review format

## Phase 2: Detection & Analysis

### Initial Triage (First 15 minutes)
1. **Threat Classification**
   - Malware infection
   - Data breach
   - Service disruption
   - Insider threat

2. **Scope Assessment**
   - Affected systems identified
   - Data exposure evaluated
   - Business impact assessed
   - Timeline established

### Technical Investigation
\`\`\`bash
# Memory dump analysis
vol.py -f memory.dmp windows.pslist
vol.py -f memory.dmp windows.netstat
vol.py -f memory.dmp windows.malfind

# Network traffic analysis
tcpdump -r capture.pcap -n | grep suspicious_ip
wireshark -r capture.pcap
\`\`\`

### Evidence Collection
\`\`\`python
# Automated evidence collection script
import subprocess
import hashlib
import datetime

def collect_evidence(target_system):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # System information
    subprocess.run(f"systeminfo > evidence_{timestamp}_sysinfo.txt", shell=True)
    
    # Network connections
    subprocess.run(f"netstat -ano > evidence_{timestamp}_netstat.txt", shell=True)
    
    # Running processes
    subprocess.run(f"tasklist /v > evidence_{timestamp}_processes.txt", shell=True)
    
    # Hash calculation for integrity
    with open(f"evidence_{timestamp}_sysinfo.txt", "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
        print(f"Evidence hash: {file_hash}")
\`\`\`

## Phase 3: Containment

### Short-term Containment
- Network isolation
- Account suspension
- Service shutdown
- Evidence preservation

### Long-term Containment
- System patching
- Configuration hardening
- Monitoring enhancement
- Access control review

## Phase 4: Eradication & Recovery

### Threat Removal
\`\`\`bash
# Malware removal example
clamav-daemon --update
clamscan -r --remove /suspected/path

# IOC hunting with YARA
yara -r malware_rules.yar /target/directory
\`\`\`

### System Restoration
- Clean system deployment
- Data restoration from backups
- Service functionality testing
- Security control validation

## Phase 5: Post-Incident Activities

### Lessons Learned Session
- Timeline review
- Response effectiveness assessment
- Process improvement recommendations
- Training gap identification

### Documentation Updates
- Playbook refinements
- Tool configuration updates
- Contact list maintenance
- Training material updates

## Quality Assurance Framework

### Response Time Metrics
- Detection to acknowledgment: < 15 minutes
- Analysis completion: < 2 hours
- Containment implementation: < 4 hours
- Recovery completion: < 24 hours

### Evidence Chain of Custody
1. **Collection**: Who, what, when, where
2. **Transfer**: Secure handoff procedures
3. **Storage**: Encrypted, access-controlled
4. **Analysis**: Forensically sound methods`,
          prerequisites: ['Cybersecurity fundamentals', 'Digital forensics basics', 'NIST Framework knowledge'],
          expectedOutcomes: [
            'Execute structured incident response',
            'Maintain evidence integrity',
            'Comply with legal requirements',
            'Improve organizational resilience'
          ]
        }
      ]
    },
    {
      id: 'threat-intelligence',
      title: 'Threat Intelligence',
      description: 'MITRE ATT&CK framework implementation and threat hunting',
      icon: Target,
      badge: 'MITRE Certified',
      items: [
        {
          id: 'mitre-attack',
          title: 'MITRE ATT&CK Framework Implementation',
          description: 'Practical implementation of MITRE ATT&CK for threat hunting',
          type: 'tutorial',
          difficulty: 'advanced',
          estimatedTime: '90 minutes',
          content: `# MITRE ATT&CK Framework Implementation

## Framework Overview

The MITRE ATT&CK framework provides a comprehensive matrix of adversary tactics and techniques based on real-world observations.

### Tactics, Techniques, and Procedures (TTPs)

#### Initial Access (TA0001)
\`\`\`json
{
  "tactic": "Initial Access",
  "techniques": [
    {
      "id": "T1566.001",
      "name": "Spearphishing Attachment",
      "detection": "Email security gateway logs, endpoint detection",
      "mitigation": "User training, attachment sandboxing"
    },
    {
      "id": "T1190",
      "name": "Exploit Public-Facing Application",
      "detection": "Web application firewall logs, vulnerability scans",
      "mitigation": "Regular patching, web application firewall"
    }
  ]
}
\`\`\`

#### Persistence (TA0003)
\`\`\`python
# Detection script for registry persistence
import winreg
import json

def check_persistence_registry():
    persistence_keys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    ]
    
    findings = []
    
    for key_path in persistence_keys:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            i = 0
            while True:
                try:
                    name, value, type = winreg.EnumValue(key, i)
                    findings.append({
                        "key": key_path,
                        "name": name,
                        "value": value,
                        "type": type
                    })
                    i += 1
                except WindowsError:
                    break
            winreg.CloseKey(key)
        except Exception as e:
            print(f"Error accessing {key_path}: {e}")
    
    return findings
\`\`\`

## Threat Hunting Methodology

### Hypothesis-Driven Hunting
1. **Intelligence Gathering**: Threat landscape analysis
2. **Hypothesis Formation**: Based on TTPs and IOCs
3. **Data Collection**: Relevant log sources identification
4. **Analysis**: Pattern recognition and anomaly detection
5. **Validation**: Confirm or refute hypothesis

### Hunting Queries

#### PowerShell Execution Detection
\`\`\`sql
-- Splunk query for suspicious PowerShell activity
index=windows EventCode=4688 
| where match(CommandLine, "(?i)powershell.*-e[a-z]*\\s+[A-Za-z0-9+/=]+")
| stats count by Computer, User, CommandLine
| where count > 1
\`\`\`

#### Lateral Movement Detection
\`\`\`kql
// KQL query for lateral movement via WMI
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AccountName !endswith "$"
| summarize count() by AccountName, IpAddress, Computer
| where count > 10
\`\`\`

## Threat Intelligence Integration

### IOC Management
\`\`\`python
# IOC processing and enrichment
import requests
import json
from datetime import datetime

class ThreatIntelligence:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.threatintel.com/v1"
    
    def enrich_ioc(self, ioc, ioc_type):
        headers = {"Authorization": f"Bearer {self.api_key}"}
        
        response = requests.get(
            f"{self.base_url}/enrich",
            params={"indicator": ioc, "type": ioc_type},
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                "ioc": ioc,
                "type": ioc_type,
                "threat_score": data.get("threat_score", 0),
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_seen"),
                "campaigns": data.get("campaigns", []),
                "attribution": data.get("attribution", [])
            }
        return None
    
    def create_hunting_rule(self, ioc_data):
        if ioc_data["threat_score"] > 7:
            return f"""
            rule HighThreatIOC_{ioc_data['type']}
            {{
                meta:
                    description = "High threat indicator detected"
                    threat_score = {ioc_data['threat_score']}
                    attribution = "{', '.join(ioc_data['attribution'])}"
                
                strings:
                    $indicator = "{ioc_data['ioc']}"
                
                condition:
                    $indicator
            }}
            """
        return None
\`\`\`

## Automated Response Integration

### SOAR Playbook Example
\`\`\`yaml
# Security orchestration playbook
name: "MITRE T1566 Phishing Response"
trigger:
  - event_type: "email_attachment_detected"
  - threat_score: "> 8"

actions:
  1. isolate_endpoint:
     - hostname: "{{ event.hostname }}"
     - isolation_type: "network"
  
  2. collect_evidence:
     - memory_dump: true
     - process_list: true
     - network_connections: true
  
  3. notify_stakeholders:
     - security_team: true
     - incident_commander: true
     - affected_user_manager: true
  
  4. create_incident:
     - severity: "high"
     - category: "malware"
     - mitre_technique: "T1566.001"
\`\`\`

## Quality Assurance & Metrics

### Hunt Effectiveness Metrics
- **True Positive Rate**: Confirmed threats / Total alerts
- **Mean Time to Detection (MTTD)**: Average detection time
- **Mean Time to Response (MTTR)**: Average response time
- **Coverage**: % of MITRE techniques monitored

### Continuous Improvement
1. **Hunt Retrospectives**: Analyze hunt outcomes
2. **Detection Tuning**: Reduce false positives
3. **Capability Gaps**: Identify monitoring blind spots
4. **Training Updates**: Keep team skills current`,
          prerequisites: ['MITRE ATT&CK familiarity', 'SIEM/SOAR experience', 'Threat hunting basics'],
          expectedOutcomes: [
            'Implement MITRE ATT&CK mapping',
            'Develop effective hunt hypotheses',
            'Create automated detection rules',
            'Measure hunt program effectiveness'
          ]
        }
      ]
    }
  ];

  const handleSearch = (query: string) => {
    setSearchQuery(query);
  };

  const toggleBookmark = (docId: string) => {
    setBookmarkedDocs(prev => 
      prev.includes(docId) 
        ? prev.filter(id => id !== docId)
        : [...prev, docId]
    );
    
    toast({
      title: bookmarkedDocs.includes(docId) ? "Bookmark Removed" : "Bookmarked",
      description: "Documentation updated in your bookmarks",
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "Content copied to clipboard",
    });
  };

  const filteredSections = documentationSections.map(section => ({
    ...section,
    items: section.items.filter(item => 
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.content.toLowerCase().includes(searchQuery.toLowerCase())
    )
  })).filter(section => section.items.length > 0);

  const selectedDocItem = selectedDoc 
    ? documentationSections
        .flatMap(section => section.items)
        .find(item => item.id === selectedDoc)
    : null;

  return (
    <Dialog open onOpenChange={onClose}>
      <DialogContent className="max-w-7xl max-h-[90vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <BookOpen className="h-5 w-5" />
            Documentation Library
          </DialogTitle>
        </DialogHeader>

        <div className="flex h-[calc(90vh-8rem)]">
          {/* Sidebar */}
          <div className="w-80 border-r pr-4">
            {/* Search */}
            <div className="mb-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search documentation..."
                  value={searchQuery}
                  onChange={(e) => handleSearch(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>

            {/* Sections */}
            <ScrollArea className="h-full">
              <div className="space-y-2">
                {filteredSections.map((section) => (
                  <Card 
                    key={section.id} 
                    className={`cursor-pointer transition-colors ${
                      selectedSection === section.id ? 'bg-primary/10 border-primary' : 'hover:bg-muted/50'
                    }`}
                    onClick={() => setSelectedSection(section.id)}
                  >
                    <CardHeader className="pb-2">
                      <div className="flex items-center gap-2">
                        <section.icon className="h-4 w-4" />
                        <CardTitle className="text-sm">{section.title}</CardTitle>
                        {section.badge && (
                          <Badge variant="secondary" className="text-xs">
                            {section.badge}
                          </Badge>
                        )}
                      </div>
                      <CardDescription className="text-xs">
                        {section.description}
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="pt-0">
                      <div className="text-xs text-muted-foreground">
                        {section.items.length} item{section.items.length !== 1 ? 's' : ''}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </ScrollArea>
          </div>

          {/* Main Content */}
          <div className="flex-1 pl-6">
            {selectedDoc ? (
              /* Document View */
              <div className="h-full flex flex-col">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Button 
                      variant="ghost" 
                      size="sm"
                      onClick={() => setSelectedDoc(null)}
                    >
                      ← Back
                    </Button>
                    <div>
                      <h2 className="font-semibold">{selectedDocItem?.title}</h2>
                      <p className="text-sm text-muted-foreground">{selectedDocItem?.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => toggleBookmark(selectedDoc)}
                    >
                      {bookmarkedDocs.includes(selectedDoc) ? (
                        <BookmarkCheck className="h-4 w-4" />
                      ) : (
                        <Bookmark className="h-4 w-4" />
                      )}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => copyToClipboard(selectedDocItem?.content || '')}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                {selectedDocItem && (
                  <div className="flex-1 overflow-hidden">
                    <Tabs defaultValue="content" className="h-full">
                      <TabsList>
                        <TabsTrigger value="content">Content</TabsTrigger>
                        <TabsTrigger value="info">Info</TabsTrigger>
                        {selectedDocItem.qaSteps && (
                          <TabsTrigger value="qa">QA Steps</TabsTrigger>
                        )}
                      </TabsList>

                      <TabsContent value="content" className="h-full mt-4">
                        <ScrollArea className="h-full">
                          <div className="prose prose-sm max-w-none">
                            <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed">
                              {selectedDocItem.content}
                            </pre>
                          </div>
                        </ScrollArea>
                      </TabsContent>

                      <TabsContent value="info" className="mt-4">
                        <div className="grid grid-cols-2 gap-4">
                          <Card>
                            <CardHeader>
                              <CardTitle className="text-base">Document Info</CardTitle>
                            </CardHeader>
                            <CardContent className="space-y-2">
                              <div className="flex justify-between text-sm">
                                <span>Type:</span>
                                <Badge variant="outline">{selectedDocItem.type}</Badge>
                              </div>
                              <div className="flex justify-between text-sm">
                                <span>Difficulty:</span>
                                <Badge variant="outline">{selectedDocItem.difficulty}</Badge>
                              </div>
                              <div className="flex justify-between text-sm">
                                <span>Est. Time:</span>
                                <span>{selectedDocItem.estimatedTime}</span>
                              </div>
                            </CardContent>
                          </Card>

                          {selectedDocItem.prerequisites && (
                            <Card>
                              <CardHeader>
                                <CardTitle className="text-base">Prerequisites</CardTitle>
                              </CardHeader>
                              <CardContent>
                                <ul className="text-sm space-y-1">
                                  {selectedDocItem.prerequisites.map((prereq, idx) => (
                                    <li key={idx} className="flex items-center gap-2">
                                      <CheckCircle className="h-3 w-3 text-green-500" />
                                      {prereq}
                                    </li>
                                  ))}
                                </ul>
                              </CardContent>
                            </Card>
                          )}

                          {selectedDocItem.expectedOutcomes && (
                            <Card className="col-span-2">
                              <CardHeader>
                                <CardTitle className="text-base">Expected Outcomes</CardTitle>
                              </CardHeader>
                              <CardContent>
                                <ul className="text-sm space-y-1">
                                  {selectedDocItem.expectedOutcomes.map((outcome, idx) => (
                                    <li key={idx} className="flex items-center gap-2">
                                      <Star className="h-3 w-3 text-yellow-500" />
                                      {outcome}
                                    </li>
                                  ))}
                                </ul>
                              </CardContent>
                            </Card>
                          )}
                        </div>
                      </TabsContent>

                      {selectedDocItem.qaSteps && (
                        <TabsContent value="qa" className="mt-4">
                          <Card>
                            <CardHeader>
                              <CardTitle className="text-base">Quality Assurance Steps</CardTitle>
                            </CardHeader>
                            <CardContent>
                              <div className="space-y-4">
                                {selectedDocItem.qaSteps.map((step, idx) => (
                                  <div key={idx} className="border rounded-lg p-4">
                                    <h4 className="font-medium text-sm mb-2">Step {idx + 1}: {step.step}</h4>
                                    <div className="text-sm space-y-2">
                                      <div>
                                        <span className="font-medium text-green-600">Expected Result:</span>
                                        <p className="text-muted-foreground mt-1">{step.expectedResult}</p>
                                      </div>
                                      {step.troubleshooting && (
                                        <div>
                                          <span className="font-medium text-orange-600">Troubleshooting:</span>
                                          <p className="text-muted-foreground mt-1">{step.troubleshooting}</p>
                                        </div>
                                      )}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </CardContent>
                          </Card>
                        </TabsContent>
                      )}
                    </Tabs>
                  </div>
                )}
              </div>
            ) : (
              /* Section Overview */
              <div className="h-full">
                <div className="mb-6">
                  <h2 className="text-2xl font-bold mb-2">
                    {documentationSections.find(s => s.id === selectedSection)?.title}
                  </h2>
                  <p className="text-muted-foreground">
                    {documentationSections.find(s => s.id === selectedSection)?.description}
                  </p>
                </div>

                <ScrollArea className="h-[calc(100%-8rem)]">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {documentationSections
                      .find(s => s.id === selectedSection)
                      ?.items.map((item) => (
                        <Card 
                          key={item.id} 
                          className="cursor-pointer hover:shadow-md transition-shadow"
                          onClick={() => setSelectedDoc(item.id)}
                        >
                          <CardHeader>
                            <div className="flex items-start justify-between">
                              <div>
                                <CardTitle className="text-base">{item.title}</CardTitle>
                                <CardDescription className="mt-1">
                                  {item.description}
                                </CardDescription>
                              </div>
                              {bookmarkedDocs.includes(item.id) && (
                                <BookmarkCheck className="h-4 w-4 text-primary" />
                              )}
                            </div>
                          </CardHeader>
                          <CardContent>
                            <div className="flex items-center justify-between text-xs">
                              <div className="flex items-center gap-4">
                                <Badge variant="outline">{item.type}</Badge>
                                <Badge variant="outline">{item.difficulty}</Badge>
                              </div>
                              <div className="flex items-center gap-1 text-muted-foreground">
                                <Clock className="h-3 w-3" />
                                {item.estimatedTime}
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                  </div>
                </ScrollArea>
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};