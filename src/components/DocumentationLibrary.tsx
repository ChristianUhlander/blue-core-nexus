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
        },
        {
          id: 'sweden-osint-guide',
          title: 'Advanced OSINT Guide (Sweden-focused)',
          description: 'Comprehensive guide for lawful open-source information gathering in Sweden',
          type: 'guide',
          difficulty: 'advanced',
          estimatedTime: '75 minutes',
          content: `# Advanced OSINT Guide (Sweden-focused)

This guide shows lawful ways to gather open-source information in/about Sweden and how to stay compliant. It does not cover bypassing access controls, scraping where forbidden, or any activity that could facilitate harassment, discrimination, stalking, or other harms.

## 1) Legal & Ethical Grounding (read this first)

### Offentlighetsprincipen (Principle of Public Access)
**Offentlighetsprincipen** gives everyone the right to access official records; it's enshrined in Sweden's Freedom of the Press Act (TF).
- **Source**: [Regeringskansliet](https://www.regeringen.se/)
- **Reference**: [Riksdagen](https://www.riksdagen.se/)

### Public Access to Information and Secrecy Act
The **Public Access to Information and Secrecy Act (2009:400)** explains how to obtain documents and the limits (what's secret).
- **Primary**: [Regeringskansliet](https://www.regeringen.se/)
- **International**: [Natlex](https://www.ilo.org/dyn/natlex/) | [WIPO](https://www.wipo.int/)

### GDPR Compliance
**GDPR** still applies to most OSINT processing. Biometric data (incl. facial recognition used to uniquely identify someone) is a special category—generally prohibited unless a strict exception in Art. 9 applies. Swedish DPA (IMY) reiterates that face recognition is highly regulated.
- **GDPR Text**: [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- **Swedish Authority**: [IMY.se](https://www.imy.se/) - [Face Recognition Guidance](https://www.imy.se/en/news/facial-recognition-in-public-spaces/)

### Publisher's Certificate Protection
Some Swedish "people search" sites rely on **utgivningsbevis** (publisher's certificate) under YGL to claim constitutional protection; even then, IMY now says such services can be reviewed for GDPR compliance. Treat their data with caution and verify.
- **Media Authority**: [Mediemyndigheten](https://www.mediemyndigheten.se/)
- **GDPR Review**: [IMY.se](https://www.imy.se/)

### Legal Precedent Warning
**Lawful use matters**: Swedish Police were fined for using Clearview AI (unlawful biometric processing). That's a clear signal for private actors, too.
- **EDPB Decision**: [European Data Protection Board](https://edpb.europa.eu/)
- **Case Details**: [GDPR Hub](https://gdprhub.eu/)

## 2) Core Swedish Sources (what you can request)

### A. Authorities (primary data; highest reliability)

#### Skatteverket (Swedish Tax Agency)
**Folkbokföring** extracts ("personbevis") for identity/family/marital status; some info is public, some confidential. Follow their public-info process.
- **Official Site**: [Skatteverket.se](https://www.skatteverket.se/)
- **Public Info Process**: [Request Guidelines](https://www.skatteverket.se/privat/folkbokforing/sekretess.4.18e1b10334ebe8bc80001502.html)

#### Sveriges Domstolar (Courts)
You can request **allmän handling** (public documents) incl. judgments; anonymity rights; secrecy review applies. Use their request pages.
- **Main Site**: [Sveriges Domstolar](https://www.domstol.se/)
- **FOI Requests**: [Document Requests](https://www.domstol.se/amne/bestalla-domar-och-beslut/)
- **Request Form**: [Online Portal](https://www.domstol.se/amne/bestalla-domar-och-beslut/bestall-domar-och-beslut/)

#### Bolagsverket (Companies Registration Office)
Free company lookups and purchasable documents (registration certs, annual reports).
- **Company Search**: [Bolagsverket.se](https://www.bolagsverket.se/)
- **Free Search**: [Company Database](https://bolagsverket.se/be/sok)
- **Document Orders**: [E-service Portal](https://bolagsverket.se/ff/foretagsformer/aktiebolag/starta/registrera)

#### Lantmäteriet (Cadastre/Property)
**Fastighetsregistret** (official property register) with free standard extracts via e-service; details on contents.
- **Main Portal**: [Lantmateriet.se](https://www.lantmateriet.se/)
- **Property Search**: [Fastighetsregistret](https://www.lantmateriet.se/en/real-property/property-register/)
- **Extract Service**: [Min Fastighet](https://minfastighet.lantmateriet.se/)
- **API Access**: [Open Data](https://www.lantmateriet.se/en/about-lantmateriet/open-geodata/)

#### Kronofogden (Enforcement Authority)
Debt/collection information via e-services or request; they note right to anonymity when contacting them.
- **Official Site**: [Kronofogden.se](https://kronofogden.se/)
- **Anonymity Rights**: [Contact Information](https://kronofogden.se/om-kronofogden/kontakt/)

**Practice**: Prefer primary records (above) to third-party mirrors; document the source, request route, reference numbers, and dates.

### B. Private Aggregators (verify & handle carefully)

**MrKoll, Ratsit, Hitta, Eniro, Merinfo, Lexbase** etc. often hold an **utgivningsbevis** (constitutional "database" protection). Accuracy varies; information may be outdated; and there's ongoing legal debate about how GDPR applies. Use only as leads; verify against primary sources.
- **Constitutional Protection**: [Mediemyndigheten](https://www.mediemyndigheten.se/)
- **Example Sites**: [MrKoll.se](https://www.mrkoll.se/) 
- **Legal Analysis**: [Timedanowsky Law](https://timedanowsky.se/)

## 3) Facial Recognition & Image OSINT (what's actually legal/useful)

**Important**: Meta shut down its face-recognition system on Facebook and deleted the templates in 2021; crawling Facebook/Instagram for biometric identification conflicts with their terms and EU privacy rules.
- **Meta Announcement**: [About Facebook](https://about.fb.com/news/2021/11/update-on-use-of-face-recognition/)
- **News Coverage**: [CBS News](https://www.cbsnews.com/) | [WIRED](https://www.wired.com/)

### Lawful alternatives (open-web only):

#### Reverse Image Search
- **Google Images**: Standard reverse image search
- **Bing Visual Search**: Microsoft's image search
- **TinEye**: Specialized reverse image search
- Works on publicly crawled web, not private social platforms

#### PimEyes (Open Web Only)
**PimEyes** searches only the open web and explicitly does not index social media like Facebook or Instagram; it offers opt-out. Use only with a clear lawful basis and respect local law.
- **Official Site**: [PimEyes.com](https://pimeyes.com/)
- **Opt-out Process**: [Privacy Controls](https://pimeyes.com/en/privacy-policy)

### Compliance Note
In Sweden/EU, using face recognition to identify a person typically processes biometric special-category data. You must have a valid Art. 9 exception (rare in OSINT contexts) and meet GDPR's principles (necessity, proportionality, transparency, etc.). When in doubt, don't process biometrics; use non-biometric and consent-based methods instead.
- **GDPR Article 9**: [Special Categories](https://gdpr-info.eu/art-9-gdpr/)
- **Swedish Guidance**: [IMY.se](https://www.imy.se/)

## 4) A Practical, Lawful OSINT Workflow (Sweden)

### Step 1: Define scope & purpose (GDPR Art. 5)
Write down your legitimate interest or other legal basis for processing. Exclude special-category data unless a clear exception applies.

### Step 2: Start with primary registers

\`\`\`bash
# Company Investigation Workflow
curl "https://api.bolagsverket.se/companies/search?name=TargetCompany"
\`\`\`

#### Bolagsverket Company Check
- Check [Bolagsverket.se](https://www.bolagsverket.se/) for entities/roles
- Document registration numbers and dates
- Download annual reports if needed

#### Property Investigation
- Pull [Lantmäteriet](https://www.lantmateriet.se/) property extracts for addresses/ownership history if necessary
- Use **Fastighetsregistret** for official property records

#### Court Records
- Request relevant court records through [Sveriges Domstolar](https://www.domstol.se/)
- Use their official request forms

#### Tax Authority Records
- Where justified, query [Skatteverket](https://www.skatteverket.se/) for permissible folkbokföring details
- Follow their public information procedures

### Step 3: Use private directories as leads, not truth
- Cross-check MrKoll/Lexbase outputs against official sources
- Keep notes on where each datum came from and its timestamp
- Treat as unverified until confirmed
- Reference: [Mediemyndigheten](https://www.mediemyndigheten.se/)

### Step 4: Open-web media checks (non-biometric first)
- Reverse-image search on public sites
- Examine EXIF (if present) and context
- If you consider a web face-search engine (e.g., [PimEyes](https://pimeyes.com/)), confirm your lawful basis, minimize data, and record opt-out/notice steps

### Step 5: Freedom-of-Information (FOI) requests
- Use **Begär ut allmän handling** procedures
- You can request anonymously, subject to secrecy tests and fees
- Reference: [Sveriges Domstolar FOI](https://www.domstol.se/)

### Step 6: Document chain-of-custody
- Store copies of responses, headers/metadata, and your notes
- Record source URL / authority, date, what you asked for, and what was returned
- Maintain forensic integrity

## 5) OPSEC & Quality

### Minimize and partition
- Only collect what you need for the stated purpose
- Store sensitive items separately
- Set retention limits
- Follow data minimization principles

### Corroborate
- Require ≥2 independent sources for any critical assertion
- At least one primary source required
- Document confidence levels

### Respect removal processes
Even where sites have **utgivningsbevis**, some offer takedown/correction workflows; IMY provides guidance for individuals contesting listings.
- **Individual Rights**: [IMY.se](https://www.imy.se/)

## 6) Quick Source Map (cheat sheet)

| Information Type | Primary Source | URL | Notes |
|-----------------|----------------|-----|-------|
| **Identity/Residence** | Skatteverket "Public information" & personbevis | [Skatteverket.se](https://www.skatteverket.se/) | Some data confidential |
| **Companies/Officers** | Bolagsverket lookup/e-services | [Bolagsverket.se](https://www.bolagsverket.se/) | Free basic search |
| **Property** | Lantmäteriet fastighetsregistret & standard extracts | [Lantmateriet.se](https://www.lantmateriet.se/) | Official property records |
| **Debts/Enforcement** | Kronofogden info & contacts | [Kronofogden.se](https://kronofogden.se/) | Anonymity rights noted |
| **Courts** | Beställ domar/beslut, FOI guidance | [Sveriges Domstolar](https://www.domstol.se/) | Public document requests |
| **People directories** | MrKoll, Lexbase | [Mediemyndigheten](https://www.mediemyndigheten.se/) | YGL protection debated; verify |
| **Facial recognition** | PimEyes (open-web only) | [PimEyes.com](https://pimeyes.com/) | Does not search Facebook/Instagram |

## 7) Things NOT to do

### Social Media Scraping
- **Don't** try to scrape or face-search Facebook/Instagram
- Meta discontinued its tagging system and social-media crawling is restricted by both law and platform policy
- Reference: [About Facebook](https://about.fb.com/)

### Special Category Data
- **Don't** build "people files" beyond necessity
- Avoid special-category data (biometrics, health, etc.) unless a clear Art. 9 exception applies
- Reference: [GDPR Article 9](https://gdpr-info.eu/art-9-gdpr/)

### Constitutional Protection Abuse
- **Don't** rely on a site's **utgivningsbevis** to justify your own downstream processing
- Your processing still needs a lawful basis
- Reference: [Mediemyndigheten](https://www.mediemyndigheten.se/)

## 8) Template: Minimal Compliance Note (example)

\`\`\`
Purpose: Background vetting for B2B onboarding
Legal basis: Legitimate interest (GDPR Art. 6(1)(f)); no special-category data processed
Sources: Bolagsverket (2025-08-30), Lantmäteriet extract (2025-08-30), Court FOI (requested 2025-08-30)
Data minimization: Only company role, registration status, property liens; no biometrics
Retention: 12 months, then delete
Data subject rights: Contact <email>; we honor access/erasure unless legal hold applies
\`\`\`

## Quality Assurance Checklist

### Legal Compliance
- [ ] Lawful basis documented (GDPR Art. 6)
- [ ] Special category data avoided or exception documented (GDPR Art. 9)
- [ ] Swedish offentlighetsprincipen respected
- [ ] Platform terms of service reviewed
- [ ] Data minimization principle applied

### Source Verification
- [ ] Primary sources prioritized over aggregators
- [ ] Request routes documented
- [ ] Reference numbers recorded
- [ ] Publication dates verified
- [ ] Cross-reference completed

### Data Quality
- [ ] Chain of custody maintained
- [ ] Screenshots captured with timestamps
- [ ] Metadata preserved
- [ ] Confidence levels assigned
- [ ] Verification status documented

### Operational Security
- [ ] Investigator identity protected
- [ ] Secure communication channels used
- [ ] Data segregation implemented
- [ ] Access controls applied
- [ ] Retention policies defined

## Final Word

OSINT in Sweden is powerful specifically because of openness and archives. The trade-off is responsibility: prefer primary sources, avoid biometrics, and keep a clear paper trail for why you collected what you collected.

For specific use cases (e.g., vendor due diligence vs. threat intel), customize this workflow with the right forms and request routes.`,
          prerequisites: [
            'Understanding of GDPR principles',
            'Familiarity with Swedish legal system',
            'Basic OSINT methodology knowledge',
            'Knowledge of data protection laws'
          ],
          expectedOutcomes: [
            'Conduct lawful OSINT investigations in Sweden',
            'Navigate Swedish public records systems',
            'Maintain GDPR compliance throughout investigations',
            'Produce legally defensible intelligence reports',
            'Understand constitutional protections and limitations'
          ],
          qaSteps: [
            {
              step: 'Legal Basis Documentation',
              expectedResult: 'Clear lawful basis documented before any data processing',
              troubleshooting: 'If uncertain about legal basis, consult legal counsel before proceeding'
            },
            {
              step: 'Primary Source Verification',
              expectedResult: 'All critical information verified through official Swedish authorities',
              troubleshooting: 'If primary source unavailable, document limitation and seek alternative verification'
            },
            {
              step: 'GDPR Compliance Check',
              expectedResult: 'All processing activities comply with GDPR requirements',
              troubleshooting: 'Review data minimization and lawful basis if compliance issues arise'
            },
            {
              step: 'Chain of Custody Maintenance',
              expectedResult: 'Complete documentation of all sources and collection methods',
              troubleshooting: 'If documentation gaps exist, fill immediately or mark as unverified'
            }
          ],
          troubleshootingTips: [
            'If a Swedish authority denies a public record request, check if secrecy provisions apply under the Public Access to Information and Secrecy Act',
            'When facing GDPR compliance questions, consult IMY guidance documents specific to your use case',
            'If private aggregator data conflicts with official records, always prioritize the official source',
            'For complex constitutional protection questions regarding utgivningsbevis, seek legal advice from Swedish media law specialists'
          ],
          tags: ['Sweden', 'OSINT', 'GDPR', 'Legal Compliance', 'Public Records', 'Intelligence Gathering'],
          lastUpdated: '2024-08-30'
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
                                       <CheckCircle className="h-3 w-3 text-primary" />
                                       <span className="text-xs">{prereq}</span>
                                     </li>
                                   ))}
                                 </ul>
                               </CardContent>
                             </Card>
                           )}

                           {selectedDocItem.expectedOutcomes && (
                             <Card>
                               <CardHeader>
                                 <CardTitle className="text-base">Learning Outcomes</CardTitle>
                               </CardHeader>
                               <CardContent>
                                 <ul className="text-sm space-y-1">
                                   {selectedDocItem.expectedOutcomes.map((outcome, idx) => (
                                     <li key={idx} className="flex items-center gap-2">
                                       <CheckCircle className="h-3 w-3 text-accent" />
                                       <span className="text-xs">{outcome}</span>
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
                                        <span className="font-medium text-primary">Expected Result:</span>
                                        <span className="text-sm text-muted-foreground">{step.expectedResult}</span>
                                      </div>
                                      {step.troubleshooting && (
                                        <div className="mt-1">
                                          <span className="font-medium text-accent">Troubleshooting:</span>
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