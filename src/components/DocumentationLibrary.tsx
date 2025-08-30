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
        },
        {
          id: 'social-media-osint',
          title: 'Social Media Intelligence (SOCMINT) Guide',
          description: 'Advanced techniques for gathering intelligence from social media platforms ethically and legally',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '90 minutes',
          content: `# Social Media Intelligence (SOCMINT) Guide

## Introduction to Social Media Intelligence

Social Media Intelligence (SOCMINT) involves the collection and analysis of data from social media platforms to generate actionable intelligence. This guide covers ethical and legal techniques for gathering intelligence from various social media platforms.

## Core SOCMINT Principles

### 1. Legal and Ethical Framework
- **Public Information Only**: Focus on publicly available information
- **Platform Terms of Service**: Always comply with platform policies
- **Privacy Considerations**: Respect user privacy and data protection laws
- **Attribution**: Properly cite and document sources

### 2. Data Protection Compliance
- **GDPR Requirements**: Ensure compliance with European data protection regulations
- **Lawful Basis**: Establish clear legal basis for data processing
- **Data Minimization**: Collect only necessary information
- **Retention Limits**: Set appropriate data retention periods

## Platform-Specific Techniques

### Twitter/X Intelligence
\`\`\`bash
# Using Twint for Twitter OSINT (Python)
pip install twint

# Search tweets by user
twint -u username --limit 100 --csv
twint -u username --since="2024-01-01" --until="2024-12-31"

# Search by keywords
twint -s "keyword" --limit 500 --csv
twint -s "#hashtag" --geo="59.3293,18.0686,50km" # Stockholm area

# Advanced search parameters
twint -u username --replies --links --media
\`\`\`

### LinkedIn Intelligence
\`\`\`python
# LinkedIn profile analysis (manual approach)
# Note: Always respect LinkedIn's terms of service

import requests
from bs4 import BeautifulSoup

def analyze_linkedin_profile(profile_url):
    """
    Analyze publicly available LinkedIn profile information
    Only works for public profiles
    """
    # This is for educational purposes only
    # Always respect rate limits and ToS
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; OSINT-Research/1.0)'
    }
    
    # Manual analysis steps:
    # 1. Employment history
    # 2. Education background
    # 3. Professional connections
    # 4. Skills and endorsements
    # 5. Published content and articles
    
    return {
        'profile_analysis': 'manual_review_required',
        'compliance_note': 'ensure_public_profile_only'
    }
\`\`\`

### Facebook/Meta Intelligence
\`\`\`python
# Facebook OSINT (Public Information Only)
# Note: Meta has restricted API access significantly

def facebook_osint_checklist():
    """
    Manual Facebook OSINT checklist for public information
    """
    return {
        'public_posts': 'Review publicly visible posts',
        'profile_info': 'Extract publicly available profile data',
        'page_analysis': 'Analyze business pages and public groups',
        'photo_metadata': 'Extract EXIF data from downloaded public images',
        'network_analysis': 'Map public connections and interactions',
        'compliance': 'Ensure all data is publicly accessible'
    }

# Graph Search alternatives (since Graph Search was discontinued)
# Use Facebook's built-in search with specific operators
search_operators = {
    'people_search': 'People named [name] who live in [location]',
    'workplace_search': 'People who work at [company]',
    'education_search': 'People who went to [school]',
    'interest_search': 'People who like [interest]'
}
\`\`\`

### Instagram Intelligence
\`\`\`python
# Instagram OSINT techniques
import json
import re
from datetime import datetime

def instagram_profile_analysis(username):
    """
    Instagram profile analysis framework
    Note: Respect Instagram's terms of service
    """
    analysis_framework = {
        'profile_metadata': {
            'bio_analysis': 'Extract contact info, locations, interests',
            'follower_patterns': 'Analyze follower/following relationships',
            'verification_status': 'Check for verification badges',
            'business_info': 'Extract business contact information'
        },
        'content_analysis': {
            'posting_patterns': 'Analyze posting frequency and timing',
            'location_data': 'Extract geotagged location information',
            'hashtag_analysis': 'Map hashtag usage patterns',
            'story_highlights': 'Review permanent story highlights'
        },
        'advanced_techniques': {
            'image_metadata': 'Extract EXIF data from downloaded images',
            'reverse_image_search': 'Use images for reverse searches',
            'network_mapping': 'Map connections and interactions',
            'temporal_analysis': 'Timeline construction from posts'
        }
    }
    return analysis_framework

# Instagram web scraping considerations
def instagram_compliance_notes():
    return {
        'rate_limiting': 'Respect API rate limits and avoid aggressive scraping',
        'public_only': 'Only access publicly available information',
        'terms_compliance': 'Follow Instagram Terms of Service',
        'privacy_respect': 'Respect user privacy settings'
    }
\`\`\`

## Advanced SOCMINT Techniques

### Username Intelligence (USINT)
\`\`\`bash
# Sherlock - Username search across platforms
pip install sherlock-project
sherlock username

# WhatsMyName - Web-based username checker
# Visit: https://whatsmyname.app/

# Namechk - Username availability checker
# Commercial service for comprehensive username searches
\`\`\`

### Email Address Intelligence
\`\`\`python
# Holehe - Email account checker
pip install holehe
holehe email@example.com

# Email format validation and platform detection
import re
import requests

def email_intelligence(email):
    """
    Gather intelligence about email addresses
    """
    intelligence = {
        'format_validation': validate_email_format(email),
        'domain_analysis': analyze_email_domain(email),
        'platform_detection': detect_email_platforms(email),
        'breach_checking': check_data_breaches(email)
    }
    return intelligence

def validate_email_format(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None
\`\`\`

### Phone Number Intelligence (PHONINT)
\`\`\`python
# PhoneInfoga - Phone number OSINT
# Installation and usage
pip install phoneinfoga

# Command line usage
phoneinfoga scan -n "+1234567890"

# Python integration
import phonenumbers
from phonenumbers import geocoder, carrier

def phone_intelligence(phone_number):
    """
    Extract intelligence from phone numbers
    """
    try:
        parsed_number = phonenumbers.parse(phone_number, None)
        
        intelligence = {
            'country': geocoder.description_for_number(parsed_number, "en"),
            'carrier': carrier.name_for_number(parsed_number, "en"),
            'is_valid': phonenumbers.is_valid_number(parsed_number),
            'number_type': phonenumbers.number_type(parsed_number),
            'timezone': phonenumbers.timezone.time_zones_for_number(parsed_number)
        }
        return intelligence
    except phonenumbers.NumberParseException as e:
        return {'error': str(e)}
\`\`\`

## SOCMINT Tools and Platforms

### Automated Intelligence Gathering
\`\`\`python
# Social media monitoring framework
class SocialMediaMonitor:
    def __init__(self):
        self.platforms = ['twitter', 'linkedin', 'facebook', 'instagram']
        self.compliance_checker = ComplianceChecker()
    
    def monitor_keyword(self, keyword, platforms=None):
        """
        Monitor keyword across specified platforms
        """
        if platforms is None:
            platforms = self.platforms
        
        results = {}
        for platform in platforms:
            if self.compliance_checker.check_platform_access(platform):
                results[platform] = self.search_platform(platform, keyword)
        
        return results
    
    def analyze_user_activity(self, username, platform):
        """
        Analyze user activity patterns
        """
        activity_data = self.gather_user_data(username, platform)
        return {
            'posting_frequency': self.calculate_posting_frequency(activity_data),
            'engagement_patterns': self.analyze_engagement(activity_data),
            'content_themes': self.extract_content_themes(activity_data),
            'network_connections': self.map_network_connections(activity_data)
        }
\`\`\`

### Manual SOCMINT Techniques

#### Advanced Search Operators
\`\`\`
# Google dorking for social media
site:twitter.com "keyword" filetype:pdf
site:linkedin.com "company name" "job title"
site:facebook.com "location" "interest"

# Twitter advanced search operators
from:username since:2024-01-01 until:2024-12-31
"exact phrase" filter:media filter:links
near:"Stockholm" within:15mi

# LinkedIn search techniques
"job title" "company" site:linkedin.com/in/
"university" "graduation year" site:linkedin.com/in/
\`\`\`

#### Profile Analysis Framework
\`\`\`python
def comprehensive_profile_analysis(profile_data):
    """
    Comprehensive social media profile analysis
    """
    analysis = {
        'demographic_intelligence': {
            'age_estimation': estimate_age_from_content(profile_data),
            'location_analysis': extract_location_indicators(profile_data),
            'occupation_insights': identify_professional_role(profile_data),
            'education_background': extract_education_info(profile_data)
        },
        'behavioral_analysis': {
            'communication_style': analyze_writing_patterns(profile_data),
            'activity_patterns': map_activity_timeline(profile_data),
            'interest_profiling': extract_interests_and_hobbies(profile_data),
            'social_connections': analyze_network_relationships(profile_data)
        },
        'security_assessment': {
            'privacy_settings': evaluate_privacy_configuration(profile_data),
            'information_exposure': assess_information_leakage(profile_data),
            'social_engineering_risks': identify_se_vulnerabilities(profile_data)
        }
    }
    return analysis
\`\`\`

## Legal and Ethical Considerations

### GDPR Compliance for SOCMINT
\`\`\`python
class GDPRComplianceChecker:
    def __init__(self):
        self.lawful_bases = [
            'consent',
            'contract',
            'legal_obligation',
            'vital_interests',
            'public_task',
            'legitimate_interests'
        ]
    
    def assess_data_collection(self, data_type, purpose, method):
        """
        Assess GDPR compliance for social media data collection
        """
        assessment = {
            'lawful_basis_required': self.determine_lawful_basis(purpose),
            'data_minimization': self.check_data_minimization(data_type, purpose),
            'transparency_requirements': self.assess_transparency_needs(method),
            'retention_limits': self.determine_retention_period(data_type, purpose),
            'individual_rights': self.map_applicable_rights(data_type)
        }
        return assessment
    
    def generate_compliance_report(self, collection_activities):
        """
        Generate comprehensive GDPR compliance report
        """
        return {
            'compliance_status': 'assessment_required',
            'recommendations': self.generate_recommendations(collection_activities),
            'risk_assessment': self.assess_compliance_risks(collection_activities)
        }
\`\`\`

### Platform Terms of Service Compliance
\`\`\`python
def platform_compliance_guide():
    """
    Platform-specific compliance guidelines
    """
    return {
        'twitter': {
            'rate_limits': 'Respect API rate limits (300 requests/15min window)',
            'automation': 'Avoid aggressive automation that mimics human behavior',
            'data_usage': 'Comply with Developer Agreement and Policy',
            'privacy': 'Respect user privacy settings and blocking'
        },
        'linkedin': {
            'scraping_policy': 'LinkedIn prohibits automated data collection',
            'manual_research': 'Manual research on public profiles is generally acceptable',
            'api_access': 'Use official LinkedIn API for programmatic access',
            'professional_context': 'Maintain professional research context'
        },
        'facebook': {
            'public_data_only': 'Only access publicly available information',
            'graph_api': 'Use official Graph API for legitimate research',
            'respect_privacy': 'Honor user privacy settings and preferences',
            'no_fake_accounts': 'Do not create fake accounts for research'
        },
        'instagram': {
            'public_posts_only': 'Access only public posts and profiles',
            'rate_limiting': 'Avoid rapid-fire requests that trigger blocks',
            'content_rights': 'Respect intellectual property rights',
            'no_automation': 'Avoid automated following/liking behaviors'
        }
    }
\`\`\`

## Quality Assurance and Verification

### Source Verification Framework
\`\`\`python
class SourceVerification:
    def __init__(self):
        self.verification_levels = ['unverified', 'partially_verified', 'verified', 'authoritative']
    
    def verify_social_media_source(self, profile_data):
        """
        Verify authenticity of social media sources
        """
        verification_score = 0
        checks = {
            'account_age': self.check_account_age(profile_data),
            'verification_status': self.check_platform_verification(profile_data),
            'activity_patterns': self.analyze_activity_authenticity(profile_data),
            'network_connections': self.verify_connection_authenticity(profile_data),
            'content_consistency': self.check_content_consistency(profile_data)
        }
        
        # Calculate overall verification score
        for check, result in checks.items():
            verification_score += result['score']
        
        return {
            'verification_level': self.determine_verification_level(verification_score),
            'detailed_checks': checks,
            'confidence_score': verification_score / len(checks)
        }
\`\`\`

### Cross-Platform Correlation
\`\`\`python
def cross_platform_analysis(username_data):
    """
    Correlate information across multiple social media platforms
    """
    correlation_analysis = {
        'identity_consistency': check_identity_consistency(username_data),
        'timeline_correlation': correlate_activity_timelines(username_data),
        'content_themes': analyze_cross_platform_themes(username_data),
        'network_overlap': identify_network_overlaps(username_data),
        'metadata_correlation': correlate_metadata_patterns(username_data)
    }
    
    confidence_assessment = {
        'same_person_probability': calculate_same_person_probability(correlation_analysis),
        'data_reliability': assess_data_reliability(correlation_analysis),
        'verification_requirements': determine_additional_verification_needs(correlation_analysis)
    }
    
    return {
        'correlation_results': correlation_analysis,
        'confidence_assessment': confidence_assessment
    }
\`\`\`

## Operational Security for SOCMINT

### Investigator Protection
\`\`\`python
class OpsecProtocol:
    def __init__(self):
        self.protection_measures = [
            'vpn_usage',
            'browser_isolation',
            'sock_puppet_accounts',
            'activity_timing',
            'data_compartmentalization'
        ]
    
    def setup_investigation_environment(self):
        """
        Set up secure investigation environment
        """
        return {
            'network_protection': {
                'vpn_configuration': 'Use VPN with no-logs policy',
                'tor_usage': 'Consider Tor for sensitive investigations',
                'dns_protection': 'Use secure DNS servers'
            },
            'browser_setup': {
                'isolated_browser': 'Use dedicated browser for OSINT work',
                'privacy_extensions': 'Install privacy-focused extensions',
                'cookie_management': 'Regularly clear cookies and cache'
            },
            'account_management': {
                'sock_puppet_creation': 'Create believable cover accounts',
                'account_aging': 'Age accounts before use',
                'activity_patterns': 'Maintain realistic activity patterns'
            }
        }
\`\`\`

## Quality Assurance Checklist

### Pre-Investigation Planning
- [ ] Define investigation objectives and scope
- [ ] Establish legal basis for data collection
- [ ] Review applicable laws and regulations
- [ ] Set up secure investigation environment
- [ ] Prepare documentation templates

### During Investigation
- [ ] Document all sources and collection methods
- [ ] Verify information through multiple sources
- [ ] Respect platform terms of service
- [ ] Maintain operational security protocols
- [ ] Regular backup of collected intelligence

### Post-Investigation
- [ ] Verify all collected information
- [ ] Assess source reliability and credibility
- [ ] Generate comprehensive intelligence report
- [ ] Secure storage of sensitive information
- [ ] Plan for information retention and disposal

### Compliance Verification
- [ ] GDPR compliance assessment completed
- [ ] Platform terms of service reviewed
- [ ] Data minimization principles applied
- [ ] Individual privacy rights respected
- [ ] Legal review conducted where necessary

## Troubleshooting Common Issues

### Platform Access Issues
- **Account Restrictions**: If accounts get restricted, review activity patterns and reduce automation
- **Rate Limiting**: Implement proper delays between requests and respect platform limits
- **Geographic Restrictions**: Use appropriate VPN locations while respecting legal requirements

### Data Quality Issues
- **Information Verification**: Always cross-reference information from multiple sources
- **Fake Profiles**: Develop skills to identify fake or sock puppet accounts
- **Outdated Information**: Check timestamps and verify current status of information

### Legal and Ethical Concerns
- **Unclear Legal Status**: Consult with legal counsel when in doubt about collection legality
- **Privacy Violations**: Err on the side of caution and respect individual privacy rights
- **Platform Policy Changes**: Stay updated with changing platform policies and terms of service

## Advanced Techniques

### Social Network Analysis (SNA)
\`\`\`python
import networkx as nx
import matplotlib.pyplot as plt

def social_network_analysis(connections_data):
    """
    Perform social network analysis on collected data
    """
    G = nx.Graph()
    
    # Add nodes and edges based on connections data
    for connection in connections_data:
        G.add_edge(connection['source'], connection['target'], 
                  weight=connection.get('strength', 1))
    
    analysis = {
        'centrality_measures': {
            'betweenness': nx.betweenness_centrality(G),
            'closeness': nx.closeness_centrality(G),
            'degree': nx.degree_centrality(G),
            'eigenvector': nx.eigenvector_centrality(G)
        },
        'community_detection': nx.community.greedy_modularity_communities(G),
        'network_metrics': {
            'density': nx.density(G),
            'clustering': nx.average_clustering(G),
            'diameter': nx.diameter(G) if nx.is_connected(G) else 'disconnected'
        }
    }
    
    return analysis
\`\`\`

### Sentiment Analysis for Social Media
\`\`\`python
from textblob import TextBlob
import pandas as pd

def analyze_social_sentiment(posts_data):
    """
    Analyze sentiment patterns in social media posts
    """
    sentiments = []
    
    for post in posts_data:
        blob = TextBlob(post['content'])
        sentiment = {
            'post_id': post['id'],
            'polarity': blob.sentiment.polarity,
            'subjectivity': blob.sentiment.subjectivity,
            'classification': classify_sentiment(blob.sentiment.polarity)
        }
        sentiments.append(sentiment)
    
    # Aggregate analysis
    df = pd.DataFrame(sentiments)
    analysis = {
        'overall_sentiment': df['polarity'].mean(),
        'sentiment_distribution': df['classification'].value_counts().to_dict(),
        'temporal_trends': analyze_sentiment_trends(df, posts_data),
        'topic_sentiment': analyze_topic_specific_sentiment(df, posts_data)
    }
    
    return analysis

def classify_sentiment(polarity):
    if polarity > 0.1:
        return 'positive'
    elif polarity < -0.1:
        return 'negative'
    else:
        return 'neutral'
\`\`\`

This comprehensive SOCMINT guide provides ethical and legal frameworks for social media intelligence gathering, with practical techniques and compliance considerations for professional investigators and security analysts.`,
          prerequisites: [
            'Basic understanding of social media platforms',
            'Knowledge of data protection laws (GDPR)',
            'Familiarity with privacy and ethics principles',
            'Basic Python programming skills (for automation)'
          ],
          expectedOutcomes: [
            'Conduct ethical social media intelligence gathering',
            'Implement GDPR-compliant data collection practices',
            'Use advanced search techniques across platforms',
            'Perform cross-platform correlation analysis',
            'Generate high-quality intelligence reports from social media data'
          ],
          qaSteps: [
            {
              step: 'Legal Compliance Verification',
              expectedResult: 'All collection activities comply with applicable laws and platform ToS',
              troubleshooting: 'Review legal basis and platform policies if compliance issues arise'
            },
            {
              step: 'Source Verification Check',
              expectedResult: 'All sources verified and reliability assessed',
              troubleshooting: 'Use cross-platform correlation to verify suspicious sources'
            },
            {
              step: 'Data Quality Assessment',
              expectedResult: 'Collected intelligence meets quality standards',
              troubleshooting: 'Implement additional verification steps if data quality is insufficient'
            }
          ],
          troubleshootingTips: [
            'If encountering rate limits, implement proper delays and respect platform restrictions',
            'For verification issues, use multiple independent sources to confirm information',
            'When facing privacy concerns, always err on the side of caution and respect individual rights',
            'If platform policies change, immediately review and adjust collection methods'
          ],
          tags: ['SOCMINT', 'Social Media', 'Intelligence Gathering', 'GDPR', 'Privacy', 'Automation'],
          lastUpdated: '2024-08-30'
        },
        {
          id: 'visual-intelligence-guide',
          title: 'Visual Intelligence & Image OSINT Guide',
          description: 'Comprehensive guide to image analysis, reverse image search, and visual intelligence gathering techniques',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '75 minutes',
          content: `# Visual Intelligence & Image OSINT Guide

## Introduction to Visual Intelligence

Visual Intelligence (VISINT) involves the collection, analysis, and interpretation of visual content to generate actionable intelligence. This includes image analysis, reverse image searching, metadata extraction, and advanced visual recognition techniques.

## Core VISINT Principles

### 1. Image Authentication and Verification
- **Source Verification**: Confirm the original source of images
- **Metadata Analysis**: Extract and analyze EXIF data
- **Reverse Image Search**: Identify image origins and usage
- **Manipulation Detection**: Identify edited or deepfake content

### 2. Legal and Ethical Framework
- **Copyright Respect**: Honor intellectual property rights
- **Privacy Protection**: Respect individual privacy in images
- **Consent Considerations**: Understand consent requirements for image use
- **Platform Compliance**: Follow image platform terms of service

## Image Metadata Analysis (EXIF)

### EXIF Data Extraction
\`\`\`python
from PIL import Image
from PIL.ExifTags import TAGS
import json
from datetime import datetime

def extract_exif_data(image_path):
    """
    Extract comprehensive EXIF metadata from images
    """
    try:
        image = Image.open(image_path)
        exifdata = image.getexif()
        
        metadata = {}
        for tag_id in exifdata:
            tag = TAGS.get(tag_id, tag_id)
            data = exifdata.get(tag_id)
            
            # Handle special data types
            if isinstance(data, bytes):
                data = data.decode('utf-8', errors='ignore')
            
            metadata[tag] = data
        
        # Extract GPS data if available
        gps_data = extract_gps_data(exifdata)
        if gps_data:
            metadata['GPS'] = gps_data
        
        return metadata
    
    except Exception as e:
        return {'error': str(e)}

def extract_gps_data(exifdata):
    """
    Extract GPS coordinates from EXIF data
    """
    gps_info = exifdata.get(34853)  # GPS IFD tag
    if not gps_info:
        return None
    
    def convert_to_degrees(value):
        d, m, s = value
        return d + (m / 60.0) + (s / 3600.0)
    
    gps_data = {}
    
    # Extract latitude
    if 2 in gps_info and 1 in gps_info:  # Latitude and LatitudeRef
        lat = convert_to_degrees(gps_info[2])
        if gps_info[1] == 'S':
            lat = -lat
        gps_data['latitude'] = lat
    
    # Extract longitude
    if 4 in gps_info and 3 in gps_info:  # Longitude and LongitudeRef
        lon = convert_to_degrees(gps_info[4])
        if gps_info[3] == 'W':
            lon = -lon
        gps_data['longitude'] = lon
    
    return gps_data if gps_data else None

# Advanced metadata analysis
def analyze_camera_fingerprint(metadata):
    """
    Analyze camera-specific metadata for device fingerprinting
    """
    fingerprint = {
        'camera_make': metadata.get('Make', 'Unknown'),
        'camera_model': metadata.get('Model', 'Unknown'),
        'software': metadata.get('Software', 'Unknown'),
        'lens_info': metadata.get('LensModel', 'Unknown'),
        'timestamp': metadata.get('DateTime', 'Unknown'),
        'camera_settings': {
            'iso': metadata.get('ISOSpeedRatings', 'Unknown'),
            'aperture': metadata.get('FNumber', 'Unknown'),
            'shutter_speed': metadata.get('ExposureTime', 'Unknown'),
            'focal_length': metadata.get('FocalLength', 'Unknown')
        }
    }
    return fingerprint
\`\`\`

### Geolocation from Images
\`\`\`python
import requests
import folium

def geolocate_image(image_path):
    """
    Extract and analyze geolocation data from images
    """
    metadata = extract_exif_data(image_path)
    gps_data = metadata.get('GPS')
    
    if not gps_data:
        return {'status': 'no_gps_data', 'suggestion': 'Try reverse image search or visual landmark identification'}
    
    lat, lon = gps_data['latitude'], gps_data['longitude']
    
    # Reverse geocoding to get location details
    location_info = reverse_geocode(lat, lon)
    
    # Generate map visualization
    map_viz = create_location_map(lat, lon, location_info)
    
    return {
        'coordinates': {'latitude': lat, 'longitude': lon},
        'location_details': location_info,
        'map_file': map_viz,
        'accuracy_assessment': assess_gps_accuracy(metadata)
    }

def reverse_geocode(lat, lon):
    """
    Perform reverse geocoding using OpenStreetMap Nominatim
    """
    url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}"
    headers = {'User-Agent': 'OSINT-Research/1.0 (Educational Use)'}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        return {
            'display_name': data.get('display_name', 'Unknown'),
            'country': data.get('address', {}).get('country', 'Unknown'),
            'city': data.get('address', {}).get('city', 'Unknown'),
            'postcode': data.get('address', {}).get('postcode', 'Unknown'),
            'confidence': data.get('importance', 0)
        }
    except Exception as e:
        return {'error': f'Geocoding failed: {str(e)}'}

def create_location_map(lat, lon, location_info):
    """
    Create interactive map with location marker
    """
    map_center = [lat, lon]
    m = folium.Map(location=map_center, zoom_start=15)
    
    popup_text = f"Location: {location_info.get('display_name', 'Unknown')}"
    folium.Marker(
        map_center,
        popup=popup_text,
        tooltip="Image Location"
    ).add_to(m)
    
    map_filename = f"location_map_{lat}_{lon}.html"
    m.save(map_filename)
    return map_filename
\`\`\`

## Reverse Image Search Techniques

### Multi-Platform Reverse Search
\`\`\`python
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
import time

class ReverseImageSearcher:
    def __init__(self):
        self.search_engines = {
            'google': 'https://images.google.com/searchbyimage?image_url=',
            'bing': 'https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIIRP&sbisrc=UrlPaste&q=imgurl:',
            'yandex': 'https://yandex.com/images/search?rpt=imageview&url=',
            'tineye': 'https://tineye.com/search?url='
        }
    
    def search_all_engines(self, image_url):
        """
        Perform reverse image search across multiple engines
        """
        results = {}
        
        for engine, search_url in self.search_engines.items():
            try:
                results[engine] = self.search_engine(engine, image_url)
                time.sleep(2)  # Rate limiting
            except Exception as e:
                results[engine] = {'error': str(e)}
        
        return results
    
    def search_engine(self, engine, image_url):
        """
        Search specific engine for image matches
        """
        search_url = self.search_engines[engine] + image_url
        
        # Note: In production, use proper web scraping with respect to ToS
        # This is a simplified example for educational purposes
        
        return {
            'search_url': search_url,
            'matches_found': 'manual_verification_required',
            'timestamp': time.time()
        }
    
    def analyze_search_results(self, results):
        """
        Analyze and correlate results from multiple search engines
        """
        analysis = {
            'engines_searched': len(results),
            'successful_searches': len([r for r in results.values() if 'error' not in r]),
            'correlation_analysis': self.find_common_results(results),
            'credibility_assessment': self.assess_result_credibility(results)
        }
        return analysis

# TinEye API integration example
def tineye_api_search(api_key, image_url):
    """
    Use TinEye API for reverse image search
    """
    api_url = "https://api.tineye.com/rest/search/"
    
    params = {
        'key': api_key,
        'image_url': image_url,
        'limit': 100,
        'offset': 0
    }
    
    try:
        response = requests.get(api_url, params=params)
        response.raise_for_status()
        data = response.json()
        
        return {
            'total_matches': data.get('results', {}).get('total', 0),
            'matches': data.get('results', {}).get('matches', []),
            'query_time': data.get('results', {}).get('query_time', 0)
        }
    except Exception as e:
        return {'error': f'TinEye API error: {str(e)}'}
\`\`\`

### Advanced Image Analysis
\`\`\`python
import cv2
import numpy as np
from skimage import feature, measure
import hashlib

def advanced_image_analysis(image_path):
    """
    Perform advanced image analysis for OSINT purposes
    """
    image = cv2.imread(image_path)
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    analysis = {
        'technical_properties': analyze_technical_properties(image),
        'visual_features': extract_visual_features(gray),
        'text_detection': detect_text_in_image(image),
        'object_detection': detect_objects(image),
        'image_hash': generate_image_hash(image),
        'manipulation_detection': detect_manipulation(image)
    }
    
    return analysis

def analyze_technical_properties(image):
    """
    Analyze technical properties of the image
    """
    height, width, channels = image.shape
    
    return {
        'dimensions': {'width': width, 'height': height},
        'channels': channels,
        'file_size': len(cv2.imencode('.jpg', image)[1].tobytes()),
        'color_space': 'BGR',
        'aspect_ratio': round(width / height, 3),
        'resolution_category': classify_resolution(width, height)
    }

def extract_visual_features(gray_image):
    """
    Extract visual features for image comparison
    """
    # Local Binary Patterns
    lbp = feature.local_binary_pattern(gray_image, 24, 8, method='uniform')
    lbp_hist, _ = np.histogram(lbp.ravel(), bins=26, range=(0, 26))
    
    # Histogram of Oriented Gradients
    hog_features = feature.hog(gray_image, orientations=9, pixels_per_cell=(8, 8), 
                               cells_per_block=(2, 2), block_norm='L2-Hys')
    
    return {
        'lbp_histogram': lbp_hist.tolist(),
        'hog_features_length': len(hog_features),
        'edge_density': calculate_edge_density(gray_image),
        'texture_measures': calculate_texture_measures(gray_image)
    }

def detect_text_in_image(image):
    """
    Detect and extract text from images using OCR
    """
    try:
        import pytesseract
        
        # Preprocess image for better OCR
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        processed = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
        
        # Extract text
        text = pytesseract.image_to_string(processed)
        
        # Get text bounding boxes
        boxes = pytesseract.image_to_boxes(processed)
        
        return {
            'extracted_text': text.strip(),
            'text_confidence': 'high' if len(text.strip()) > 10 else 'low',
            'bounding_boxes': boxes,
            'language_detection': detect_text_language(text)
        }
    except ImportError:
        return {'error': 'Tesseract OCR not installed'}
    except Exception as e:
        return {'error': f'Text detection failed: {str(e)}'}

def generate_image_hash(image):
    """
    Generate various hash types for image comparison
    """
    # Convert to grayscale for hashing
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    # Average hash
    resized = cv2.resize(gray, (8, 8))
    avg = resized.mean()
    avg_hash = ''.join(['1' if pixel > avg else '0' for pixel in resized.flatten()])
    
    # Difference hash
    resized_diff = cv2.resize(gray, (9, 8))
    diff_hash = ''.join(['1' if resized_diff[i][j] > resized_diff[i][j+1] else '0' 
                        for i in range(8) for j in range(8)])
    
    # MD5 hash of raw data
    md5_hash = hashlib.md5(image.tobytes()).hexdigest()
    
    return {
        'average_hash': avg_hash,
        'difference_hash': diff_hash,
        'md5_hash': md5_hash,
        'image_signature': generate_image_signature(gray)
    }
\`\`\`

## Facial Recognition and Analysis

### Ethical Facial Recognition
\`\`\`python
import cv2
import numpy as np

class EthicalFaceAnalysis:
    def __init__(self):
        self.compliance_checker = FaceRecognitionCompliance()
        self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    
    def analyze_faces_ethically(self, image_path, consent_verified=False):
        """
        Perform ethical face analysis with privacy protections
        """
        if not consent_verified:
            return {
                'error': 'Consent required for facial analysis',
                'compliance_note': 'Facial recognition requires explicit consent under GDPR Art. 9'
            }
        
        image = cv2.imread(image_path)
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Detect faces
        faces = self.face_cascade.detectMultiScale(gray, 1.1, 4)
        
        analysis = {
            'faces_detected': len(faces),
            'face_locations': [{'x': x, 'y': y, 'width': w, 'height': h} 
                              for (x, y, w, h) in faces],
            'privacy_protection': 'enabled',
            'consent_verified': consent_verified,
            'gdpr_compliance': self.compliance_checker.verify_compliance()
        }
        
        return analysis
    
    def anonymize_faces(self, image_path, output_path):
        """
        Anonymize faces in images for privacy protection
        """
        image = cv2.imread(image_path)
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        faces = self.face_cascade.detectMultiScale(gray, 1.1, 4)
        
        for (x, y, w, h) in faces:
            # Apply blur to face region
            face_region = image[y:y+h, x:x+w]
            blurred_face = cv2.GaussianBlur(face_region, (99, 99), 30)
            image[y:y+h, x:x+w] = blurred_face
        
        cv2.imwrite(output_path, image)
        
        return {
            'anonymized_faces': len(faces),
            'output_file': output_path,
            'privacy_protection': 'applied'
        }

class FaceRecognitionCompliance:
    """
    Ensure compliance with facial recognition regulations
    """
    def __init__(self):
        self.gdpr_requirements = [
            'explicit_consent',
            'lawful_basis',
            'data_minimization',
            'transparency',
            'right_to_erasure'
        ]
    
    def verify_compliance(self):
        """
        Verify GDPR compliance for facial recognition
        """
        return {
            'biometric_data_category': 'special_category',
            'article_9_exception_required': True,
            'consent_requirements': 'explicit_and_informed',
            'data_protection_impact_assessment': 'required',
            'privacy_by_design': 'mandatory'
        }
\`\`\`

## Visual Intelligence Platforms

### PimEyes Integration (Educational Example)
\`\`\`python
class VisualIntelligencePlatforms:
    def __init__(self):
        self.platforms = {
            'pimeyes': {
                'description': 'Facial recognition search engine',
                'compliance_notes': 'Check consent and legal basis before use',
                'scope': 'Open web only, no social media indexing'
            },
            'tineye': {
                'description': 'Reverse image search engine',
                'compliance_notes': 'Generally safer for copyright and usage tracking',
                'scope': 'Web images, copyright verification'
            },
            'google_images': {
                'description': 'Google reverse image search',
                'compliance_notes': 'Respect image copyrights and privacy',
                'scope': 'Broad web coverage'
            },
            'yandex_images': {
                'description': 'Yandex reverse image search',
                'compliance_notes': 'Strong for Eastern European content',
                'scope': 'Global with regional strength'
            }
        }
    
    def platform_compliance_check(self, platform_name, intended_use):
        """
        Check compliance requirements for visual intelligence platforms
        """
        platform = self.platforms.get(platform_name, {})
        
        compliance_check = {
            'platform': platform_name,
            'intended_use': intended_use,
            'compliance_requirements': self.assess_compliance_needs(intended_use),
            'platform_limitations': platform.get('compliance_notes', 'Unknown'),
            'recommended_approach': self.recommend_approach(platform_name, intended_use)
        }
        
        return compliance_check
    
    def assess_compliance_needs(self, intended_use):
        """
        Assess compliance needs based on intended use
        """
        compliance_map = {
            'copyright_verification': ['fair_use_assessment', 'dmca_compliance'],
            'person_identification': ['gdpr_article_9', 'explicit_consent', 'lawful_basis'],
            'image_source_verification': ['journalism_exemption', 'public_interest'],
            'security_investigation': ['legitimate_interest', 'necessity_test']
        }
        
        return compliance_map.get(intended_use, ['general_privacy_compliance'])
\`\`\`

## Image Manipulation Detection

### Deepfake and Manipulation Detection
\`\`\`python
import cv2
import numpy as np
from scipy import fftpack

def detect_image_manipulation(image_path):
    """
    Detect potential image manipulation and editing
    """
    image = cv2.imread(image_path)
    
    manipulation_analysis = {
        'compression_artifacts': analyze_compression_artifacts(image),
        'noise_analysis': analyze_noise_patterns(image),
        'edge_consistency': analyze_edge_consistency(image),
        'lighting_analysis': analyze_lighting_consistency(image),
        'metadata_analysis': check_metadata_inconsistencies(image_path),
        'frequency_analysis': perform_frequency_analysis(image)
    }
    
    manipulation_score = calculate_manipulation_score(manipulation_analysis)
    
    return {
        'manipulation_likelihood': manipulation_score,
        'detailed_analysis': manipulation_analysis,
        'recommendation': generate_verification_recommendation(manipulation_score)
    }

def analyze_compression_artifacts(image):
    """
    Analyze JPEG compression artifacts for manipulation detection
    """
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    # Calculate DCT coefficients
    dct = cv2.dct(np.float32(gray))
    
    # Analyze for double compression
    compression_analysis = {
        'double_compression_indicators': detect_double_compression(dct),
        'quality_estimation': estimate_jpeg_quality(image),
        'block_artifacts': detect_block_artifacts(gray)
    }
    
    return compression_analysis

def analyze_noise_patterns(image):
    """
    Analyze noise patterns for manipulation detection
    """
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    # Calculate noise variance in different regions
    regions = divide_image_regions(gray)
    noise_variances = [calculate_noise_variance(region) for region in regions]
    
    noise_analysis = {
        'noise_variance_consistency': np.std(noise_variances),
        'noise_pattern_anomalies': detect_noise_anomalies(gray),
        'splicing_indicators': detect_splicing_artifacts(gray)
    }
    
    return noise_analysis

def perform_frequency_analysis(image):
    """
    Perform frequency domain analysis for manipulation detection
    """
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    # FFT analysis
    fft = fftpack.fft2(gray)
    fft_shift = fftpack.fftshift(fft)
    magnitude_spectrum = np.log(np.abs(fft_shift) + 1)
    
    frequency_analysis = {
        'periodic_artifacts': detect_periodic_artifacts(magnitude_spectrum),
        'frequency_anomalies': detect_frequency_anomalies(magnitude_spectrum),
        'grid_patterns': detect_grid_patterns(magnitude_spectrum)
    }
    
    return frequency_analysis
\`\`\`

## Operational Security for Visual Intelligence

### Secure Image Handling
\`\`\`python
import os
import shutil
import hashlib
from cryptography.fernet import Fernet

class SecureImageHandler:
    def __init__(self):
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
    
    def secure_image_download(self, url, output_dir):
        """
        Securely download and store images for analysis
        """
        try:
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            # Generate secure filename
            url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
            filename = f"image_{url_hash}.jpg"
            filepath = os.path.join(output_dir, filename)
            
            # Download and encrypt
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Calculate file hash for integrity
            file_hash = self.calculate_file_hash(filepath)
            
            # Encrypt sensitive images
            encrypted_path = self.encrypt_image(filepath)
            
            return {
                'original_url': url,
                'local_path': filepath,
                'encrypted_path': encrypted_path,
                'file_hash': file_hash,
                'download_timestamp': time.time()
            }
            
        except Exception as e:
            return {'error': f'Download failed: {str(e)}'}
    
    def encrypt_image(self, image_path):
        """
        Encrypt sensitive images for secure storage
        """
        with open(image_path, 'rb') as f:
            image_data = f.read()
        
        encrypted_data = self.cipher_suite.encrypt(image_data)
        
        encrypted_path = image_path + '.enc'
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Remove original unencrypted file
        os.remove(image_path)
        
        return encrypted_path
    
    def decrypt_image(self, encrypted_path):
        """
        Decrypt images for analysis
        """
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = self.cipher_suite.decrypt(encrypted_data)
        
        decrypted_path = encrypted_path.replace('.enc', '_decrypted.jpg')
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)
        
        return decrypted_path
    
    def calculate_file_hash(self, filepath):
        """
        Calculate file hash for integrity verification
        """
        sha256_hash = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
\`\`\`

## Quality Assurance and Verification

### Image Intelligence Verification Framework
\`\`\`python
class ImageIntelligenceVerification:
    def __init__(self):
        self.verification_standards = [
            'source_authentication',
            'technical_verification',
            'temporal_verification',
            'contextual_verification'
        ]
    
    def comprehensive_image_verification(self, image_data, source_info):
        """
        Perform comprehensive verification of image intelligence
        """
        verification_results = {
            'source_verification': self.verify_image_source(source_info),
            'technical_verification': self.verify_technical_authenticity(image_data),
            'temporal_verification': self.verify_temporal_consistency(image_data),
            'contextual_verification': self.verify_contextual_consistency(image_data),
            'cross_reference_verification': self.cross_reference_image(image_data)
        }
        
        overall_confidence = self.calculate_confidence_score(verification_results)
        
        return {
            'verification_results': verification_results,
            'confidence_score': overall_confidence,
            'reliability_assessment': self.assess_reliability(overall_confidence),
            'recommendations': self.generate_verification_recommendations(verification_results)
        }
    
    def verify_image_source(self, source_info):
        """
        Verify the credibility and authenticity of image sources
        """
        source_verification = {
            'source_type': source_info.get('type', 'unknown'),
            'source_credibility': self.assess_source_credibility(source_info),
            'chain_of_custody': self.verify_chain_of_custody(source_info),
            'publication_context': self.analyze_publication_context(source_info)
        }
        
        return source_verification
    
    def cross_reference_image(self, image_data):
        """
        Cross-reference image across multiple sources and databases
        """
        cross_reference_results = {
            'reverse_search_results': self.perform_multi_engine_search(image_data),
            'database_matches': self.check_image_databases(image_data),
            'timeline_correlation': self.correlate_temporal_data(image_data),
            'geospatial_correlation': self.correlate_geospatial_data(image_data)
        }
        
        return cross_reference_results
\`\`\`

## Quality Assurance Checklist

### Pre-Analysis Planning
- [ ] Define intelligence objectives for visual analysis
- [ ] Establish legal basis for image collection and analysis
- [ ] Set up secure environment for image handling
- [ ] Prepare necessary tools and platforms
- [ ] Review compliance requirements

### During Analysis
- [ ] Document all image sources and collection methods
- [ ] Extract and preserve original metadata
- [ ] Perform multi-platform reverse image searches
- [ ] Verify technical authenticity of images
- [ ] Maintain chain of custody for evidence

### Post-Analysis Verification
- [ ] Cross-reference findings across multiple sources
- [ ] Verify geolocation and temporal data
- [ ] Assess manipulation likelihood
- [ ] Generate confidence scores for all findings
- [ ] Document verification methodology

### Compliance and Ethics
- [ ] GDPR compliance verified for facial recognition
- [ ] Copyright and intellectual property respected
- [ ] Platform terms of service followed
- [ ] Privacy rights protected throughout process
- [ ] Appropriate consent obtained where required

This comprehensive Visual Intelligence guide provides ethical and legal frameworks for image analysis and visual intelligence gathering, with practical techniques for professional investigators and security analysts.`,
          prerequisites: [
            'Basic understanding of image formats and metadata',
            'Familiarity with privacy and data protection laws',
            'Python programming skills for automation',
            'Knowledge of reverse image search techniques'
          ],
          expectedOutcomes: [
            'Extract and analyze comprehensive image metadata',
            'Perform effective reverse image searches across platforms',
            'Detect image manipulation and deepfakes',
            'Conduct ethical facial recognition analysis',
            'Implement secure image handling procedures'
          ],
          qaSteps: [
            {
              step: 'Metadata Extraction Verification',
              expectedResult: 'Complete EXIF data extracted and analyzed',
              troubleshooting: 'If metadata is missing, image may have been processed or stripped'
            },
            {
              step: 'Reverse Search Correlation',
              expectedResult: 'Consistent results across multiple search engines',
              troubleshooting: 'Discrepancies may indicate image manipulation or unique content'
            },
            {
              step: 'Legal Compliance Check',
              expectedResult: 'All analysis activities comply with applicable laws',
              troubleshooting: 'Review consent requirements and privacy laws if compliance issues arise'
            }
          ],
          troubleshootingTips: [
            'If EXIF data is missing, the image may have been processed through social media or editing software',
            'For poor reverse search results, try cropping different portions of the image',
            'When facing privacy concerns with facial recognition, always obtain explicit consent',
            'If manipulation is suspected, use multiple detection methods for verification'
          ],
          tags: ['VISINT', 'Image Analysis', 'Reverse Search', 'EXIF', 'Facial Recognition', 'Privacy'],
          lastUpdated: '2024-08-30'
        },
        {
          id: 'domain-network-intelligence',
          title: 'Domain & Network Intelligence Guide',
          description: 'Comprehensive guide to domain analysis, DNS investigation, and network infrastructure intelligence',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '85 minutes',
          content: `# Domain & Network Intelligence Guide

## Introduction to Domain Intelligence

Domain and Network Intelligence (DOMINT/NETINT) involves the systematic collection and analysis of domain registration data, DNS records, network infrastructure, and related technical intelligence to support cybersecurity investigations and threat hunting.

## Core Domain Intelligence Concepts

### 1. Domain Registration Analysis
- **WHOIS Data**: Registration details, registrant information, and administrative contacts
- **Registration History**: Historical changes in domain ownership and configuration
- **Registrar Analysis**: Patterns in registrar choice and registration practices
- **Domain Age Assessment**: Age as an indicator of legitimacy and reputation

### 2. DNS Infrastructure Analysis
- **DNS Records**: Comprehensive analysis of all DNS record types
- **Subdomain Discovery**: Mapping of complete domain infrastructure
- **DNS History**: Historical DNS changes and configuration evolution
- **DNS Security**: DNSSEC implementation and security posture

## WHOIS and Domain Registration Intelligence

### Advanced WHOIS Analysis
\`\`\`python
import whois
import requests
import json
from datetime import datetime, timedelta
import dns.resolver

class DomainIntelligence:
    def __init__(self):
        self.whois_sources = [
            'whois.iana.org',
            'whois.verisign-grs.com',
            'whois.registry.in'
        ]
    
    def comprehensive_domain_analysis(self, domain):
        """
        Perform comprehensive domain intelligence gathering
        """
        analysis = {
            'whois_analysis': self.analyze_whois_data(domain),
            'dns_analysis': self.analyze_dns_records(domain),
            'subdomain_discovery': self.discover_subdomains(domain),
            'historical_analysis': self.analyze_domain_history(domain),
            'reputation_analysis': self.analyze_domain_reputation(domain),
            'security_assessment': self.assess_domain_security(domain)
        }
        
        # Generate risk assessment
        risk_score = self.calculate_domain_risk_score(analysis)
        analysis['risk_assessment'] = {
            'score': risk_score,
            'classification': self.classify_risk_level(risk_score),
            'factors': self.identify_risk_factors(analysis)
        }
        
        return analysis
    
    def analyze_whois_data(self, domain):
        """
        Extract and analyze WHOIS registration data
        """
        try:
            w = whois.whois(domain)
            
            whois_analysis = {
                'registrant_info': {
                    'name': w.registrant_name,
                    'organization': w.registrant_org,
                    'email': w.registrant_email,
                    'phone': w.registrant_phone,
                    'address': {
                        'street': w.registrant_street,
                        'city': w.registrant_city,
                        'state': w.registrant_state,
                        'postal_code': w.registrant_postal_code,
                        'country': w.registrant_country
                    }
                },
                'registration_details': {
                    'registrar': w.registrar,
                    'creation_date': w.creation_date,
                    'expiration_date': w.expiration_date,
                    'updated_date': w.updated_date,
                    'status': w.status
                },
                'technical_contacts': {
                    'admin_email': w.admin_email,
                    'tech_email': w.tech_email,
                    'billing_email': w.billing_email
                },
                'name_servers': w.name_servers,
                'dnssec': w.dnssec if hasattr(w, 'dnssec') else 'Unknown'
            }
            
            # Calculate domain age
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                domain_age = (datetime.now() - creation_date).days
                whois_analysis['domain_age_days'] = domain_age
                whois_analysis['domain_age_assessment'] = self.assess_domain_age(domain_age)
            
            return whois_analysis
            
        except Exception as e:
            return {'error': f'WHOIS lookup failed: {str(e)}'}
    
    def analyze_dns_records(self, domain):
        """
        Comprehensive DNS record analysis
        """
        dns_analysis = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_analysis[record_type] = [str(rdata) for rdata in answers]
                
                # Special analysis for specific record types
                if record_type == 'TXT':
                    dns_analysis['txt_analysis'] = self.analyze_txt_records(answers)
                elif record_type == 'MX':
                    dns_analysis['mx_analysis'] = self.analyze_mx_records(answers)
                elif record_type == 'NS':
                    dns_analysis['ns_analysis'] = self.analyze_ns_records(answers)
                    
            except dns.resolver.NXDOMAIN:
                dns_analysis[record_type] = 'NXDOMAIN'
            except dns.resolver.NoAnswer:
                dns_analysis[record_type] = 'No records found'
            except Exception as e:
                dns_analysis[record_type] = f'Error: {str(e)}'
        
        return dns_analysis
    
    def discover_subdomains(self, domain):
        """
        Discover subdomains using multiple techniques
        """
        subdomain_discovery = {
            'dictionary_based': self.dictionary_subdomain_search(domain),
            'certificate_transparency': self.ct_subdomain_discovery(domain),
            'dns_bruteforce': self.dns_bruteforce_subdomains(domain),
            'search_engine_discovery': self.search_engine_subdomain_discovery(domain)
        }
        
        # Consolidate and deduplicate results
        all_subdomains = set()
        for method, results in subdomain_discovery.items():
            if isinstance(results, list):
                all_subdomains.update(results)
        
        subdomain_discovery['consolidated_results'] = {
            'total_subdomains': len(all_subdomains),
            'unique_subdomains': sorted(list(all_subdomains)),
            'discovery_methods_used': len([m for m in subdomain_discovery.keys() if subdomain_discovery[m]])
        }
        
        return subdomain_discovery
    
    def analyze_domain_history(self, domain):
        """
        Analyze historical domain data and changes
        """
        historical_analysis = {
            'whois_history': self.get_whois_history(domain),
            'dns_history': self.get_dns_history(domain),
            'ip_history': self.get_ip_history(domain),
            'subdomain_history': self.get_subdomain_history(domain)
        }
        
        # Analyze change patterns
        historical_analysis['change_analysis'] = {
            'registration_changes': self.analyze_registration_changes(historical_analysis['whois_history']),
            'infrastructure_changes': self.analyze_infrastructure_changes(historical_analysis['dns_history']),
            'hosting_changes': self.analyze_hosting_changes(historical_analysis['ip_history'])
        }
        
        return historical_analysis

# DNS Analysis Helper Functions
def analyze_txt_records(txt_records):
    """
    Analyze TXT records for security and configuration information
    """
    txt_analysis = {
        'spf_records': [],
        'dkim_records': [],
        'dmarc_records': [],
        'verification_records': [],
        'other_records': []
    }
    
    for record in txt_records:
        record_str = str(record)
        
        if record_str.startswith('v=spf1'):
            txt_analysis['spf_records'].append(record_str)
        elif 'dkim' in record_str.lower() or record_str.startswith('k='):
            txt_analysis['dkim_records'].append(record_str)
        elif record_str.startswith('v=DMARC1'):
            txt_analysis['dmarc_records'].append(record_str)
        elif any(verify_string in record_str for verify_string in ['google-site-verification', 'MS=', 'facebook-domain-verification']):
            txt_analysis['verification_records'].append(record_str)
        else:
            txt_analysis['other_records'].append(record_str)
    
    # Email security assessment
    txt_analysis['email_security_assessment'] = {
        'spf_configured': len(txt_analysis['spf_records']) > 0,
        'dkim_configured': len(txt_analysis['dkim_records']) > 0,
        'dmarc_configured': len(txt_analysis['dmarc_records']) > 0,
        'security_score': calculate_email_security_score(txt_analysis)
    }
    
    return txt_analysis

def calculate_email_security_score(txt_analysis):
    """
    Calculate email security score based on SPF, DKIM, DMARC configuration
    """
    score = 0
    if txt_analysis['spf_configured']:
        score += 30
    if txt_analysis['dkim_configured']:
        score += 30
    if txt_analysis['dmarc_configured']:
        score += 40
    
    return score
\`\`\`

### Subdomain Discovery and Enumeration
\`\`\`bash
# Using Subfinder for passive subdomain discovery
subfinder -d example.com -all -recursive -o subdomains.txt

# Using Amass for comprehensive subdomain enumeration
amass enum -passive -d example.com -o amass_results.txt
amass enum -active -d example.com -brute -w wordlist.txt

# Using DNSRecon for DNS enumeration
dnsrecon -d example.com -t std,rvl,brt,srv,axfr

# Certificate Transparency log search
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Using Gobuster for subdomain brute forcing
gobuster dns -d example.com -w /usr/share/wordlists/subdomains.txt -o gobuster_results.txt
\`\`\`

### Advanced DNS Analysis
\`\`\`python
import dns.resolver
import dns.zone
import dns.query
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import requests

class AdvancedDNSAnalysis:
    def __init__(self):
        self.public_dns_servers = [
            '8.8.8.8',  # Google
            '1.1.1.1',  # Cloudflare
            '208.67.222.222',  # OpenDNS
            '9.9.9.9'   # Quad9
        ]
    
    def comprehensive_dns_analysis(self, domain):
        """
        Perform comprehensive DNS analysis across multiple servers
        """
        analysis = {
            'dns_server_comparison': self.compare_dns_responses(domain),
            'dns_propagation_check': self.check_dns_propagation(domain),
            'dns_security_analysis': self.analyze_dns_security(domain),
            'dns_performance_analysis': self.analyze_dns_performance(domain),
            'dns_infrastructure_mapping': self.map_dns_infrastructure(domain)
        }
        
        return analysis
    
    def compare_dns_responses(self, domain):
        """
        Compare DNS responses across different DNS servers
        """
        results = {}
        
        for dns_server in self.public_dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                
                server_results = {}
                for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                    try:
                        answers = resolver.resolve(domain, record_type)
                        server_results[record_type] = [str(rdata) for rdata in answers]
                    except:
                        server_results[record_type] = None
                
                results[dns_server] = server_results
                
            except Exception as e:
                results[dns_server] = {'error': str(e)}
        
        # Analyze consistency across servers
        consistency_analysis = self.analyze_dns_consistency(results)
        
        return {
            'server_responses': results,
            'consistency_analysis': consistency_analysis
        }
    
    def analyze_dns_security(self, domain):
        """
        Analyze DNS security configuration and vulnerabilities
        """
        security_analysis = {
            'dnssec_status': self.check_dnssec_status(domain),
            'dns_over_https': self.check_doh_support(domain),
            'dns_over_tls': self.check_dot_support(domain),
            'cache_poisoning_resistance': self.assess_cache_poisoning_resistance(domain),
            'dns_amplification_risk': self.assess_dns_amplification_risk(domain)
        }
        
        return security_analysis
    
    def check_dnssec_status(self, domain):
        """
        Check DNSSEC implementation and validation
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.use_edns(0, dns.flags.DO, 4096)
            
            # Query for DNSKEY records
            try:
                dnskey_response = resolver.resolve(domain, 'DNSKEY')
                dnssec_enabled = len(dnskey_response) > 0
            except:
                dnssec_enabled = False
            
            # Query for DS records
            try:
                ds_response = resolver.resolve(domain, 'DS')
                ds_records = len(ds_response) > 0
            except:
                ds_records = False
            
            return {
                'dnssec_enabled': dnssec_enabled,
                'ds_records_present': ds_records,
                'validation_status': 'secure' if dnssec_enabled and ds_records else 'insecure'
            }
            
        except Exception as e:
            return {'error': f'DNSSEC check failed: {str(e)}'}
    
    def map_dns_infrastructure(self, domain):
        """
        Map complete DNS infrastructure for a domain
        """
        infrastructure_map = {
            'authoritative_nameservers': self.get_authoritative_nameservers(domain),
            'nameserver_geolocation': self.geolocate_nameservers(domain),
            'nameserver_providers': self.identify_nameserver_providers(domain),
            'dns_load_balancing': self.analyze_dns_load_balancing(domain),
            'cdn_detection': self.detect_cdn_usage(domain)
        }
        
        return infrastructure_map
\`\`\`

## Network Infrastructure Analysis

### IP Address Intelligence
\`\`\`python
import ipaddress
import requests
import socket
import subprocess
import json

class NetworkIntelligence:
    def __init__(self):
        self.ip_intelligence_apis = {
            'abuseipdb': 'https://api.abuseipdb.com/api/v2/check',
            'virustotal': 'https://www.virustotal.com/vtapi/v2/ip-address/report',
            'shodan': 'https://api.shodan.io/shodan/host',
            'maxmind': 'https://geoip.maxmind.com/geoip/v2.1/insights'
        }
    
    def comprehensive_ip_analysis(self, ip_address):
        """
        Perform comprehensive IP address analysis
        """
        if not self.validate_ip_address(ip_address):
            return {'error': 'Invalid IP address format'}
        
        analysis = {
            'basic_info': self.get_basic_ip_info(ip_address),
            'geolocation': self.get_ip_geolocation(ip_address),
            'reputation_analysis': self.analyze_ip_reputation(ip_address),
            'network_analysis': self.analyze_network_context(ip_address),
            'service_detection': self.detect_running_services(ip_address),
            'threat_intelligence': self.gather_threat_intelligence(ip_address)
        }
        
        return analysis
    
    def get_basic_ip_info(self, ip_address):
        """
        Get basic information about an IP address
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            basic_info = {
                'ip_address': str(ip_obj),
                'version': ip_obj.version,
                'is_private': ip_obj.is_private,
                'is_multicast': ip_obj.is_multicast,
                'is_reserved': ip_obj.is_reserved,
                'is_loopback': ip_obj.is_loopback,
                'ptr_record': self.get_ptr_record(ip_address),
                'asn_info': self.get_asn_info(ip_address)
            }
            
            return basic_info
            
        except Exception as e:
            return {'error': f'IP analysis failed: {str(e)}'}
    
    def get_ptr_record(self, ip_address):
        """
        Get PTR (reverse DNS) record for IP address
        """
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except:
            return None
    
    def get_asn_info(self, ip_address):
        """
        Get ASN (Autonomous System Number) information
        """
        try:
            # Using ipinfo.io API for ASN information
            response = requests.get(f'https://ipinfo.io/{ip_address}/json')
            if response.status_code == 200:
                data = response.json()
                return {
                    'asn': data.get('org', '').split()[0] if data.get('org') else None,
                    'organization': data.get('org', ''),
                    'isp': data.get('org', ''),
                    'country': data.get('country', ''),
                    'region': data.get('region', ''),
                    'city': data.get('city', '')
                }
        except:
            pass
        
        return None
    
    def analyze_network_context(self, ip_address):
        """
        Analyze network context and related infrastructure
        """
        network_context = {
            'network_range': self.identify_network_range(ip_address),
            'neighboring_hosts': self.scan_neighboring_hosts(ip_address),
            'routing_analysis': self.analyze_routing_path(ip_address),
            'network_topology': self.map_network_topology(ip_address)
        }
        
        return network_context
    
    def detect_running_services(self, ip_address):
        """
        Detect services running on the IP address
        """
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3389, 5432, 3306]
        
        service_detection = {
            'open_ports': [],
            'service_banners': {},
            'web_servers': self.detect_web_servers(ip_address),
            'mail_servers': self.detect_mail_servers(ip_address),
            'dns_servers': self.detect_dns_servers(ip_address)
        }
        
        # Port scanning (use with caution and proper authorization)
        for port in common_ports:
            if self.check_port_open(ip_address, port):
                service_detection['open_ports'].append(port)
                banner = self.grab_service_banner(ip_address, port)
                if banner:
                    service_detection['service_banners'][port] = banner
        
        return service_detection
    
    def check_port_open(self, ip_address, port, timeout=3):
        """
        Check if a specific port is open
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            return result == 0
        except:
            return False
\`\`\`

### Certificate Analysis and SSL Intelligence
\`\`\`python
import ssl
import socket
import OpenSSL.crypto
from datetime import datetime
import requests

class CertificateIntelligence:
    def __init__(self):
        self.certificate_transparency_logs = [
            'https://crt.sh',
            'https://certspotter.com/api/v0/certs',
            'https://api.certspotter.com/v1/issuances'
        ]
    
    def analyze_ssl_certificate(self, hostname, port=443):
        """
        Analyze SSL/TLS certificate for a hostname
        """
        try:
            # Get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
            
            # Parse certificate
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
            
            certificate_analysis = {
                'basic_info': self.extract_basic_cert_info(cert),
                'subject_info': self.extract_subject_info(cert),
                'issuer_info': self.extract_issuer_info(cert),
                'validity_info': self.extract_validity_info(cert),
                'extension_analysis': self.analyze_cert_extensions(cert),
                'security_analysis': self.analyze_cert_security(cert),
                'transparency_logs': self.check_certificate_transparency(hostname)
            }
            
            return certificate_analysis
            
        except Exception as e:
            return {'error': f'Certificate analysis failed: {str(e)}'}
    
    def extract_basic_cert_info(self, cert):
        """
        Extract basic certificate information
        """
        return {
            'version': cert.get_version() + 1,
            'serial_number': str(cert.get_serial_number()),
            'signature_algorithm': cert.get_signature_algorithm().decode('utf-8'),
            'public_key_algorithm': cert.get_pubkey().type(),
            'public_key_bits': cert.get_pubkey().bits()
        }
    
    def extract_subject_info(self, cert):
        """
        Extract certificate subject information
        """
        subject = cert.get_subject()
        return {
            'common_name': subject.commonName,
            'organization': subject.organizationName,
            'organizational_unit': subject.organizationalUnitName,
            'locality': subject.localityName,
            'state': subject.stateOrProvinceName,
            'country': subject.countryName,
            'email': subject.emailAddress
        }
    
    def check_certificate_transparency(self, hostname):
        """
        Check Certificate Transparency logs for the hostname
        """
        ct_results = {}
        
        try:
            # Query crt.sh
            response = requests.get(f'https://crt.sh/?q={hostname}&output=json')
            if response.status_code == 200:
                crt_sh_data = response.json()
                ct_results['crt_sh'] = {
                    'certificates_found': len(crt_sh_data),
                    'issuers': list(set([cert.get('issuer_name', 'Unknown') for cert in crt_sh_data])),
                    'earliest_cert': min([cert.get('not_before', '') for cert in crt_sh_data]) if crt_sh_data else None,
                    'latest_cert': max([cert.get('not_after', '') for cert in crt_sh_data]) if crt_sh_data else None
                }
        except Exception as e:
            ct_results['crt_sh'] = {'error': str(e)}
        
        return ct_results
    
    def analyze_cert_security(self, cert):
        """
        Analyze certificate security characteristics
        """
        security_analysis = {
            'key_size_adequate': cert.get_pubkey().bits() >= 2048,
            'signature_algorithm_secure': self.assess_signature_algorithm(cert.get_signature_algorithm().decode('utf-8')),
            'validity_period_reasonable': self.assess_validity_period(cert),
            'weak_key_detection': self.detect_weak_keys(cert),
            'revocation_status': self.check_revocation_status(cert)
        }
        
        # Calculate overall security score
        security_score = sum([
            30 if security_analysis['key_size_adequate'] else 0,
            25 if security_analysis['signature_algorithm_secure'] else 0,
            20 if security_analysis['validity_period_reasonable'] else 0,
            25 if not security_analysis['weak_key_detection'] else 0
        ])
        
        security_analysis['security_score'] = security_score
        security_analysis['security_grade'] = self.calculate_security_grade(security_score)
        
        return security_analysis
\`\`\`

## Network Mapping and Topology Discovery

### Infrastructure Mapping
\`\`\`python
import nmap
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import networkx as nx

class NetworkTopologyMapper:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.discovered_hosts = {}
        self.network_graph = nx.Graph()
    
    def map_network_infrastructure(self, target_network):
        """
        Map network infrastructure and topology
        """
        if not self.validate_network_range(target_network):
            return {'error': 'Invalid network range'}
        
        infrastructure_map = {
            'network_discovery': self.discover_active_hosts(target_network),
            'service_enumeration': self.enumerate_services(target_network),
            'topology_mapping': self.map_network_topology(),
            'vulnerability_assessment': self.assess_network_vulnerabilities(),
            'traffic_analysis': self.analyze_network_traffic()
        }
        
        return infrastructure_map
    
    def discover_active_hosts(self, network_range):
        """
        Discover active hosts in network range
        """
        try:
            # Ping sweep to discover active hosts
            self.nm.scan(hosts=network_range, arguments='-sn')
            
            active_hosts = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    host_info = {
                        'ip': host,
                        'hostname': self.nm[host].hostname(),
                        'status': self.nm[host].state(),
                        'mac_address': self.get_mac_address(host),
                        'vendor': self.identify_vendor(host)
                    }
                    active_hosts.append(host_info)
                    self.discovered_hosts[host] = host_info
            
            return {
                'total_hosts_discovered': len(active_hosts),
                'active_hosts': active_hosts,
                'network_range_scanned': network_range
            }
            
        except Exception as e:
            return {'error': f'Host discovery failed: {str(e)}'}
    
    def enumerate_services(self, network_range):
        """
        Enumerate services on discovered hosts
        """
        service_enumeration = {}
        
        # Common service ports
        service_ports = '22,23,25,53,80,110,143,443,993,995,1433,3389,5432,3306'
        
        try:
            self.nm.scan(hosts=network_range, ports=service_ports, arguments='-sV -sC')
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    host_services = []
                    
                    for protocol in self.nm[host].all_protocols():
                        ports = self.nm[host][protocol].keys()
                        
                        for port in ports:
                            port_info = self.nm[host][protocol][port]
                            service_info = {
                                'port': port,
                                'protocol': protocol,
                                'state': port_info['state'],
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extrainfo': port_info.get('extrainfo', ''),
                                'cpe': port_info.get('cpe', '')
                            }
                            host_services.append(service_info)
                    
                    service_enumeration[host] = {
                        'total_open_ports': len(host_services),
                        'services': host_services,
                        'os_detection': self.detect_operating_system(host)
                    }
            
            return service_enumeration
            
        except Exception as e:
            return {'error': f'Service enumeration failed: {str(e)}'}
    
    def map_network_topology(self):
        """
        Map network topology and relationships
        """
        topology_map = {
            'network_segments': self.identify_network_segments(),
            'routing_paths': self.trace_routing_paths(),
            'network_devices': self.identify_network_devices(),
            'vlan_detection': self.detect_vlans(),
            'network_graph': self.build_network_graph()
        }
        
        return topology_map
    
    def identify_network_segments(self):
        """
        Identify different network segments and subnets
        """
        segments = {}
        
        for host_ip, host_info in self.discovered_hosts.items():
            try:
                ip_obj = ipaddress.ip_address(host_ip)
                
                # Determine likely subnet based on common network configurations
                for prefix_len in [24, 25, 26, 27, 28]:
                    network = ipaddress.ip_network(f"{host_ip}/{prefix_len}", strict=False)
                    network_str = str(network)
                    
                    if network_str not in segments:
                        segments[network_str] = {
                            'network': network_str,
                            'hosts': [],
                            'prefix_length': prefix_len
                        }
                    
                    segments[network_str]['hosts'].append(host_ip)
            
            except Exception as e:
                continue
        
        return segments
    
    def build_network_graph(self):
        """
        Build network graph representation
        """
        # Add nodes for each discovered host
        for host_ip, host_info in self.discovered_hosts.items():
            self.network_graph.add_node(host_ip, **host_info)
        
        # Add edges based on network connectivity
        for host_ip in self.discovered_hosts.keys():
            # Trace route to identify network paths
            routing_path = self.trace_route_to_host(host_ip)
            if routing_path:
                for i in range(len(routing_path) - 1):
                    self.network_graph.add_edge(routing_path[i], routing_path[i + 1])
        
        # Calculate network metrics
        graph_metrics = {
            'total_nodes': self.network_graph.number_of_nodes(),
            'total_edges': self.network_graph.number_of_edges(),
            'network_density': nx.density(self.network_graph),
            'connected_components': nx.number_connected_components(self.network_graph),
            'average_clustering': nx.average_clustering(self.network_graph)
        }
        
        return {
            'graph_representation': self.network_graph,
            'graph_metrics': graph_metrics,
            'centrality_analysis': self.analyze_network_centrality()
        }
\`\`\`

## Quality Assurance and Verification

### Domain Intelligence Verification
\`\`\`python
class DomainIntelligenceVerification:
    def __init__(self):
        self.verification_sources = [
            'whois.iana.org',
            'whois.verisign-grs.com',
            'rdap.org'
        ]
    
    def verify_domain_intelligence(self, domain, intelligence_data):
        """
        Verify collected domain intelligence across multiple sources
        """
        verification_results = {
            'whois_verification': self.cross_verify_whois_data(domain, intelligence_data.get('whois_analysis', {})),
            'dns_verification': self.verify_dns_consistency(domain, intelligence_data.get('dns_analysis', {})),
            'historical_verification': self.verify_historical_accuracy(domain, intelligence_data.get('historical_analysis', {})),
            'reputation_verification': self.verify_reputation_data(domain, intelligence_data.get('reputation_analysis', {}))
        }
        
        overall_confidence = self.calculate_confidence_score(verification_results)
        
        return {
            'verification_results': verification_results,
            'confidence_score': overall_confidence,
            'reliability_assessment': self.assess_data_reliability(overall_confidence),
            'recommendations': self.generate_verification_recommendations(verification_results)
        }
    
    def cross_verify_whois_data(self, domain, whois_data):
        """
        Cross-verify WHOIS data across multiple sources
        """
        verification_results = {}
        
        for source in self.verification_sources:
            try:
                # Query alternative WHOIS source
                alt_whois_data = self.query_alternative_whois(domain, source)
                
                # Compare key fields
                comparison = {
                    'registrar_match': self.compare_registrar_data(whois_data, alt_whois_data),
                    'contact_match': self.compare_contact_data(whois_data, alt_whois_data),
                    'date_match': self.compare_date_data(whois_data, alt_whois_data)
                }
                
                verification_results[source] = comparison
                
            except Exception as e:
                verification_results[source] = {'error': str(e)}
        
        return verification_results
    
    def assess_data_reliability(self, confidence_score):
        """
        Assess overall data reliability based on verification results
        """
        if confidence_score >= 90:
            return {
                'level': 'high',
                'description': 'Data verified across multiple sources with high consistency',
                'recommended_use': 'Suitable for critical decision making'
            }
        elif confidence_score >= 70:
            return {
                'level': 'medium',
                'description': 'Data partially verified with some inconsistencies',
                'recommended_use': 'Suitable for general analysis with caution'
            }
        else:
            return {
                'level': 'low',
                'description': 'Data verification failed or shows significant inconsistencies',
                'recommended_use': 'Requires additional verification before use'
            }
\`\`\`

## Quality Assurance Checklist

### Pre-Investigation Planning
- [ ] Define domain intelligence objectives and scope
- [ ] Identify target domains and network ranges
- [ ] Establish legal authorization for network scanning
- [ ] Set up secure investigation environment
- [ ] Prepare necessary tools and API access

### During Investigation
- [ ] Document all data sources and collection timestamps
- [ ] Cross-verify critical information across multiple sources
- [ ] Respect rate limits and avoid aggressive scanning
- [ ] Maintain detailed logs of all investigative activities
- [ ] Monitor for detection and adjust techniques as needed

### Post-Investigation Analysis
- [ ] Verify all collected intelligence for accuracy
- [ ] Correlate findings across different data types
- [ ] Assess confidence levels for all intelligence
- [ ] Generate comprehensive intelligence report
- [ ] Archive investigation data securely

### Legal and Ethical Compliance
- [ ] Ensure proper authorization for all scanning activities
- [ ] Respect network ownership and boundaries
- [ ] Follow responsible disclosure for vulnerabilities
- [ ] Maintain confidentiality of sensitive information
- [ ] Document compliance with applicable laws and regulations

This comprehensive Domain & Network Intelligence guide provides ethical and legal frameworks for infrastructure analysis and network intelligence gathering, with practical techniques for professional investigators and security analysts.`,
          prerequisites: [
            'Basic understanding of DNS and networking concepts',
            'Knowledge of TCP/IP protocols and network architecture',
            'Familiarity with command-line tools and Python programming',
            'Understanding of legal frameworks for network scanning'
          ],
          expectedOutcomes: [
            'Conduct comprehensive domain registration analysis',
            'Perform advanced DNS enumeration and analysis',
            'Map network infrastructure and topology',
            'Analyze SSL/TLS certificates and security configurations',
            'Implement ethical network reconnaissance techniques'
          ],
          qaSteps: [
            {
              step: 'Domain Registration Verification',
              expectedResult: 'Accurate WHOIS data collected and verified across multiple sources',
              troubleshooting: 'If WHOIS data is inconsistent, check multiple registrar sources and RDAP'
            },
            {
              step: 'DNS Analysis Validation',
              expectedResult: 'Complete DNS record enumeration with consistent results',
              troubleshooting: 'If DNS results vary, check DNS propagation and server consistency'
            },
            {
              step: 'Network Scanning Authorization',
              expectedResult: 'Proper authorization obtained for all network scanning activities',
              troubleshooting: 'Ensure explicit permission before scanning any network infrastructure'
            }
          ],
          troubleshootingTips: [
            'If WHOIS lookups fail, try alternative WHOIS servers or RDAP services',
            'For DNS inconsistencies, check multiple DNS servers and propagation status',
            'When network scanning is blocked, verify permissions and adjust scanning intensity',
            'If subdomain discovery yields poor results, try multiple enumeration techniques'
          ],
          tags: ['DOMINT', 'NETINT', 'DNS Analysis', 'Network Mapping', 'Infrastructure Intelligence'],
          lastUpdated: '2024-08-30'
        },
        {
          id: 'threat-intelligence-guide',
          title: 'Threat Intelligence & IOC Analysis Guide',
          description: 'Advanced guide to threat intelligence gathering, IOC analysis, and adversary tracking techniques',
          type: 'guide',
          difficulty: 'advanced',
          estimatedTime: '95 minutes',
          content: `# Threat Intelligence & IOC Analysis Guide

## Introduction to Threat Intelligence

Threat Intelligence involves the collection, analysis, and dissemination of information about current and potential threats to an organization's security. This guide covers advanced techniques for gathering, analyzing, and operationalizing threat intelligence data.

## Core Threat Intelligence Concepts

### 1. Threat Intelligence Types
- **Strategic Intelligence**: High-level threat landscape analysis for executive decision-making
- **Tactical Intelligence**: Technical indicators and TTPs for security operations teams
- **Operational Intelligence**: Campaign-specific information for incident response
- **Technical Intelligence**: IOCs, malware analysis, and infrastructure details

### 2. Intelligence Requirements
- **PIRs (Priority Intelligence Requirements)**: Critical questions that intelligence must answer
- **SIRs (Specific Intelligence Requirements)**: Detailed technical requirements
- **Collection Requirements**: Specific data sources and collection methods needed

## IOC (Indicators of Compromise) Analysis

### IOC Collection and Normalization
\`\`\`python
import hashlib
import ipaddress
import re
import json
import requests
from datetime import datetime, timedelta
import yara

class IOCAnalyzer:
    def __init__(self):
        self.ioc_types = {
            'hash': {
                'md5': r'^[a-fA-F0-9]{32}$',
                'sha1': r'^[a-fA-F0-9]{40}$',
                'sha256': r'^[a-fA-F0-9]{64}$'
            },
            'network': {
                'ipv4': r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$',
                'ipv6': r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$',
                'domain': r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$',
                'url': r'^https?://[^\s/$.?#].[^\s]*$'
            },
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        }
        
        self.threat_intel_feeds = {
            'misp': 'https://misp-project.org/',
            'otx': 'https://otx.alienvault.com/',
            'virustotal': 'https://www.virustotal.com/',
            'threatcrowd': 'https://threatcrowd.org/',
            'hybrid_analysis': 'https://hybrid-analysis.com/'
        }
    
    def analyze_ioc_batch(self, ioc_list):
        """
        Analyze a batch of IOCs and enrich with threat intelligence
        """
        analysis_results = {
            'total_iocs': len(ioc_list),
            'ioc_classification': {},
            'enrichment_results': {},
            'correlation_analysis': {},
            'risk_assessment': {}
        }
        
        # Classify IOCs by type
        classified_iocs = self.classify_iocs(ioc_list)
        analysis_results['ioc_classification'] = classified_iocs
        
        # Enrich each IOC with threat intelligence
        for ioc_type, iocs in classified_iocs.items():
            for ioc in iocs:
                enrichment = self.enrich_ioc(ioc, ioc_type)
                analysis_results['enrichment_results'][ioc] = enrichment
        
        # Perform correlation analysis
        correlations = self.correlate_iocs(analysis_results['enrichment_results'])
        analysis_results['correlation_analysis'] = correlations
        
        # Generate risk assessment
        risk_assessment = self.assess_ioc_risk(analysis_results)
        analysis_results['risk_assessment'] = risk_assessment
        
        return analysis_results
    
    def classify_iocs(self, ioc_list):
        """
        Classify IOCs by type using regex patterns
        """
        classified = {
            'hash_md5': [],
            'hash_sha1': [],
            'hash_sha256': [],
            'ip_address': [],
            'domain': [],
            'url': [],
            'email': [],
            'unknown': []
        }
        
        for ioc in ioc_list:
            ioc = ioc.strip()
            classified_type = self.identify_ioc_type(ioc)
            
            if classified_type in classified:
                classified[classified_type].append(ioc)
            else:
                classified['unknown'].append(ioc)
        
        return {k: v for k, v in classified.items() if v}  # Remove empty categories
    
    def identify_ioc_type(self, ioc):
        """
        Identify the type of an IOC using pattern matching
        """
        # Check hash types
        for hash_type, pattern in self.ioc_types['hash'].items():
            if re.match(pattern, ioc):
                return f'hash_{hash_type}'
        
        # Check network indicators
        for net_type, pattern in self.ioc_types['network'].items():
            if re.match(pattern, ioc):
                if net_type in ['ipv4', 'ipv6']:
                    return 'ip_address'
                return net_type
        
        # Check email
        if re.match(self.ioc_types['email'], ioc):
            return 'email'
        
        return 'unknown'
    
    def enrich_ioc(self, ioc, ioc_type):
        """
        Enrich IOC with threat intelligence from multiple sources
        """
        enrichment_data = {
            'ioc': ioc,
            'type': ioc_type,
            'timestamp': datetime.utcnow().isoformat(),
            'sources': {},
            'reputation_score': 0,
            'threat_associations': [],
            'first_seen': None,
            'last_seen': None,
            'confidence_score': 0
        }
        
        # Query multiple threat intelligence sources
        if ioc_type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
            enrichment_data['sources']['virustotal'] = self.query_virustotal_hash(ioc)
            enrichment_data['sources']['hybrid_analysis'] = self.query_hybrid_analysis(ioc)
        
        elif ioc_type == 'ip_address':
            enrichment_data['sources']['virustotal'] = self.query_virustotal_ip(ioc)
            enrichment_data['sources']['abuseipdb'] = self.query_abuseipdb(ioc)
            enrichment_data['sources']['shodan'] = self.query_shodan_ip(ioc)
        
        elif ioc_type == 'domain':
            enrichment_data['sources']['virustotal'] = self.query_virustotal_domain(ioc)
            enrichment_data['sources']['threatcrowd'] = self.query_threatcrowd_domain(ioc)
        
        elif ioc_type == 'url':
            enrichment_data['sources']['virustotal'] = self.query_virustotal_url(ioc)
            enrichment_data['sources']['urlvoid'] = self.query_urlvoid(ioc)
        
        # Calculate aggregate reputation score
        enrichment_data['reputation_score'] = self.calculate_reputation_score(enrichment_data['sources'])
        
        # Extract threat associations
        enrichment_data['threat_associations'] = self.extract_threat_associations(enrichment_data['sources'])
        
        # Calculate confidence score
        enrichment_data['confidence_score'] = self.calculate_confidence_score(enrichment_data['sources'])
        
        return enrichment_data

# VirusTotal Integration
def query_virustotal_hash(self, file_hash):
    """
    Query VirusTotal for file hash information
    """
    # Note: Requires API key - this is a template
    api_key = 'YOUR_VT_API_KEY'
    
    headers = {'x-apikey': api_key}
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            
            return {
                'malicious_votes': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
                'total_engines': sum(data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).values()),
                'first_submission': data.get('data', {}).get('attributes', {}).get('first_submission_date'),
                'last_analysis': data.get('data', {}).get('attributes', {}).get('last_analysis_date'),
                'file_type': data.get('data', {}).get('attributes', {}).get('type_description'),
                'file_size': data.get('data', {}).get('attributes', {}).get('size'),
                'md5': data.get('data', {}).get('attributes', {}).get('md5'),
                'sha1': data.get('data', {}).get('attributes', {}).get('sha1'),
                'sha256': data.get('data', {}).get('attributes', {}).get('sha256')
            }
        else:
            return {'error': f'VT API error: {response.status_code}'}
    
    except Exception as e:
        return {'error': f'VT query failed: {str(e)}'}

def correlate_iocs(self, enrichment_results):
    """
    Correlate IOCs to identify relationships and campaigns
    """
    correlation_analysis = {
        'malware_families': {},
        'infrastructure_clusters': {},
        'temporal_correlations': {},
        'campaign_indicators': {},
        'attribution_indicators': {}
    }
    
    # Group IOCs by malware family
    for ioc, enrichment in enrichment_results.items():
        threat_associations = enrichment.get('threat_associations', [])
        
        for association in threat_associations:
            malware_family = association.get('malware_family')
            if malware_family:
                if malware_family not in correlation_analysis['malware_families']:
                    correlation_analysis['malware_families'][malware_family] = []
                correlation_analysis['malware_families'][malware_family].append(ioc)
    
    # Identify infrastructure clusters
    ip_domains = {}
    for ioc, enrichment in enrichment_results.items():
        if enrichment.get('type') == 'ip_address':
            # Find domains resolving to this IP
            associated_domains = self.find_associated_domains(ioc)
            if associated_domains:
                ip_domains[ioc] = associated_domains
    
    correlation_analysis['infrastructure_clusters'] = ip_domains
    
    # Temporal correlation analysis
    temporal_groups = self.group_by_temporal_proximity(enrichment_results)
    correlation_analysis['temporal_correlations'] = temporal_groups
    
    return correlation_analysis
\`\`\`

### Advanced Threat Hunting with YARA
\`\`\`python
import yara
import os
import hashlib
from pathlib import Path

class YARAHunter:
    def __init__(self):
        self.rule_categories = {
            'malware_families': [],
            'apt_groups': [],
            'generic_indicators': [],
            'packer_detection': [],
            'crypto_detection': []
        }
        
        self.custom_rules = {
            'suspicious_strings': '''
                rule SuspiciousStrings {
                    meta:
                        description = "Detects suspicious strings commonly used in malware"
                        author = "Threat Intel Team"
                        date = "2024-08-30"
                    
                    strings:
                        $s1 = "cmd.exe" ascii
                        $s2 = "powershell" ascii
                        $s3 = "certutil" ascii
                        $s4 = "bitsadmin" ascii
                        $s5 = "regsvr32" ascii
                        $s6 = "rundll32" ascii
                        $s7 = "wscript" ascii
                        $s8 = "cscript" ascii
                    
                    condition:
                        any of ($s*)
                }
            ''',
            
            'network_indicators': '''
                rule NetworkIndicators {
                    meta:
                        description = "Detects network-related indicators"
                        author = "Threat Intel Team"
                        date = "2024-08-30"
                    
                    strings:
                        $url1 = /https?:\\/\\/[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/ ascii
                        $ip1 = /\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b/ ascii
                        $email1 = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/ ascii
                    
                    condition:
                        any of ($url*, $ip*, $email*)
                }
            ''',
            
            'encryption_indicators': '''
                rule EncryptionIndicators {
                    meta:
                        description = "Detects encryption and obfuscation indicators"
                        author = "Threat Intel Team"
                        date = "2024-08-30"
                    
                    strings:
                        $crypto1 = "AES" ascii
                        $crypto2 = "RSA" ascii
                        $crypto3 = "base64" ascii
                        $crypto4 = "XOR" ascii
                        $obfusc1 = { 33 C0 33 C9 33 D2 }  // Common XOR pattern
                        $obfusc2 = { 55 8B EC 83 EC }     // Function prologue
                    
                    condition:
                        any of ($crypto*) or any of ($obfusc*)
                }
            '''
        }
    
    def hunt_with_yara(self, target_path, rule_set='all'):
        """
        Perform YARA-based threat hunting on files
        """
        hunting_results = {
            'total_files_scanned': 0,
            'matches_found': [],
            'rule_statistics': {},
            'threat_indicators': {},
            'false_positive_analysis': {}
        }
        
        # Compile YARA rules
        compiled_rules = self.compile_yara_rules(rule_set)
        
        # Scan target files
        if os.path.isfile(target_path):
            files_to_scan = [target_path]
        elif os.path.isdir(target_path):
            files_to_scan = self.get_files_recursively(target_path)
        else:
            return {'error': 'Invalid target path'}
        
        for file_path in files_to_scan:
            try:
                file_results = self.scan_file_with_yara(file_path, compiled_rules)
                if file_results['matches']:
                    hunting_results['matches_found'].append(file_results)
                
                hunting_results['total_files_scanned'] += 1
                
            except Exception as e:
                continue
        
        # Analyze results
        hunting_results['rule_statistics'] = self.analyze_rule_statistics(hunting_results['matches_found'])
        hunting_results['threat_indicators'] = self.extract_threat_indicators(hunting_results['matches_found'])
        
        return hunting_results
    
    def compile_yara_rules(self, rule_set):
        """
        Compile YARA rules based on specified rule set
        """
        rules_to_compile = {}
        
        if rule_set == 'all' or rule_set == 'custom':
            rules_to_compile.update(self.custom_rules)
        
        if rule_set == 'all' or rule_set == 'external':
            # Load external YARA rules (if available)
            external_rules = self.load_external_yara_rules()
            rules_to_compile.update(external_rules)
        
        try:
            compiled_rules = yara.compile(sources=rules_to_compile)
            return compiled_rules
        except Exception as e:
            return {'error': f'YARA compilation failed: {str(e)}'}
    
    def scan_file_with_yara(self, file_path, compiled_rules):
        """
        Scan individual file with compiled YARA rules
        """
        scan_results = {
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'file_hash': self.calculate_file_hash(file_path),
            'matches': [],
            'scan_timestamp': datetime.utcnow().isoformat()
        }
        
        try:
            matches = compiled_rules.match(file_path)
            
            for match in matches:
                match_data = {
                    'rule_name': match.rule,
                    'namespace': match.namespace,
                    'metadata': dict(match.meta),
                    'strings': [{'offset': s.offset, 'identifier': s.identifier, 'matches': s.instances} 
                              for s in match.strings],
                    'tags': match.tags
                }
                scan_results['matches'].append(match_data)
        
        except Exception as e:
            scan_results['error'] = str(e)
        
        return scan_results
    
    def create_custom_hunting_rule(self, rule_name, indicators, metadata=None):
        """
        Create custom YARA rule for specific hunting campaign
        """
        if metadata is None:
            metadata = {
                'description': f'Custom hunting rule for {rule_name}',
                'author': 'Threat Intel Team',
                'date': datetime.now().strftime('%Y-%m-%d')
            }
        
        rule_template = f'''
            rule {rule_name} {{
                meta:
        '''
        
        # Add metadata
        for key, value in metadata.items():
            rule_template += f'        {key} = "{value}"\n'
        
        rule_template += '\n    strings:\n'
        
        # Add string indicators
        for i, indicator in enumerate(indicators, 1):
            if isinstance(indicator, dict):
                string_def = f'        $s{i} = {indicator["pattern"]}'
                if indicator.get('modifier'):
                    string_def += f' {indicator["modifier"]}'
                rule_template += string_def + '\n'
            else:
                rule_template += f'        $s{i} = "{indicator}" ascii\n'
        
        rule_template += '\n    condition:\n        any of ($s*)\n}'
        
        return rule_template
\`\`\`

## Threat Actor Attribution and Tracking

### Attribution Framework
\`\`\`python
import json
import requests
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime

@dataclass
class ThreatActor:
    name: str
    aliases: List[str]
    country: Optional[str]
    motivation: str
    first_seen: datetime
    last_seen: datetime
    tools: List[str]
    ttps: List[str]
    targets: List[str]
    confidence_level: str

class ThreatActorTracker:
    def __init__(self):
        self.known_actors = {}
        self.attribution_frameworks = {
            'mitre_attack': 'https://attack.mitre.org/',
            'malpedia': 'https://malpedia.caad.fkie.fraunhofer.de/',
            'apt_notes': 'https://github.com/aptnotes/data',
            'threat_connect': 'https://threatconnect.com/'
        }
        
        self.attribution_indicators = {
            'technical': [
                'code_reuse',
                'tool_preferences',
                'infrastructure_patterns',
                'malware_families',
                'encryption_methods'
            ],
            'behavioral': [
                'target_selection',
                'attack_timing',
                'operational_patterns',
                'social_engineering_methods',
                'post_exploitation_activities'
            ],
            'linguistic': [
                'language_artifacts',
                'timezone_patterns',
                'cultural_references',
                'translation_quality',
                'keyboard_layouts'
            ]
        }
    
    def analyze_threat_actor_attribution(self, campaign_data):
        """
        Analyze campaign data to identify potential threat actor attribution
        """
        attribution_analysis = {
            'technical_attribution': self.analyze_technical_indicators(campaign_data),
            'behavioral_attribution': self.analyze_behavioral_patterns(campaign_data),
            'infrastructure_attribution': self.analyze_infrastructure_patterns(campaign_data),
            'temporal_attribution': self.analyze_temporal_patterns(campaign_data),
            'linguistic_attribution': self.analyze_linguistic_indicators(campaign_data),
            'confidence_assessment': {}
        }
        
        # Calculate attribution confidence
        confidence_scores = self.calculate_attribution_confidence(attribution_analysis)
        attribution_analysis['confidence_assessment'] = confidence_scores
        
        # Generate candidate threat actors
        candidate_actors = self.identify_candidate_actors(attribution_analysis)
        attribution_analysis['candidate_actors'] = candidate_actors
        
        return attribution_analysis
    
    def analyze_technical_indicators(self, campaign_data):
        """
        Analyze technical indicators for attribution
        """
        technical_analysis = {
            'malware_families': self.identify_malware_families(campaign_data),
            'tool_usage': self.analyze_tool_usage(campaign_data),
            'code_similarities': self.analyze_code_similarities(campaign_data),
            'infrastructure_reuse': self.analyze_infrastructure_reuse(campaign_data),
            'encryption_patterns': self.analyze_encryption_patterns(campaign_data)
        }
        
        return technical_analysis
    
    def analyze_behavioral_patterns(self, campaign_data):
        """
        Analyze behavioral patterns for attribution
        """
        behavioral_analysis = {
            'target_sectors': self.analyze_target_sectors(campaign_data),
            'geographic_focus': self.analyze_geographic_targeting(campaign_data),
            'attack_sophistication': self.assess_attack_sophistication(campaign_data),
            'operational_timing': self.analyze_operational_timing(campaign_data),
            'persistence_methods': self.analyze_persistence_methods(campaign_data)
        }
        
        return behavioral_analysis
    
    def analyze_infrastructure_patterns(self, campaign_data):
        """
        Analyze infrastructure patterns for attribution
        """
        infrastructure_analysis = {
            'domain_patterns': self.analyze_domain_registration_patterns(campaign_data),
            'hosting_providers': self.analyze_hosting_provider_preferences(campaign_data),
            'registration_artifacts': self.analyze_registration_artifacts(campaign_data),
            'network_topology': self.analyze_network_topology_patterns(campaign_data),
            'certificate_patterns': self.analyze_certificate_patterns(campaign_data)
        }
        
        return infrastructure_analysis
    
    def create_threat_actor_profile(self, actor_name, analysis_data):
        """
        Create comprehensive threat actor profile
        """
        threat_actor_profile = {
            'basic_information': {
                'name': actor_name,
                'aliases': self.extract_known_aliases(actor_name),
                'first_observed': self.get_first_observation_date(actor_name),
                'last_activity': self.get_last_activity_date(actor_name),
                'activity_status': self.assess_activity_status(actor_name)
            },
            'attribution_assessment': {
                'confidence_level': self.calculate_overall_confidence(analysis_data),
                'attribution_evidence': self.compile_attribution_evidence(analysis_data),
                'alternative_hypotheses': self.generate_alternative_hypotheses(analysis_data)
            },
            'capabilities_assessment': {
                'technical_sophistication': self.assess_technical_capabilities(analysis_data),
                'operational_capabilities': self.assess_operational_capabilities(analysis_data),
                'resource_level': self.assess_resource_level(analysis_data)
            },
            'targeting_analysis': {
                'primary_targets': self.identify_primary_targets(analysis_data),
                'geographic_focus': self.identify_geographic_focus(analysis_data),
                'sector_preferences': self.identify_sector_preferences(analysis_data)
            },
            'ttps_analysis': {
                'attack_vectors': self.identify_attack_vectors(analysis_data),
                'persistence_methods': self.identify_persistence_methods(analysis_data),
                'evasion_techniques': self.identify_evasion_techniques(analysis_data),
                'exfiltration_methods': self.identify_exfiltration_methods(analysis_data)
            }
        }
        
        return threat_actor_profile
\`\`\`

## MITRE ATT&CK Framework Integration

### ATT&CK Mapping and Analysis
\`\`\`python
import requests
import json
from collections import defaultdict

class MITREAttackAnalyzer:
    def __init__(self):
        self.attack_data_url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
        self.attack_data = None
        self.techniques_by_tactic = defaultdict(list)
        self.techniques_by_group = defaultdict(list)
        self.load_attack_data()
    
    def load_attack_data(self):
        """
        Load MITRE ATT&CK framework data
        """
        try:
            response = requests.get(self.attack_data_url)
            self.attack_data = response.json()
            self.process_attack_data()
        except Exception as e:
            print(f"Failed to load ATT&CK data: {e}")
    
    def process_attack_data(self):
        """
        Process ATT&CK data for analysis
        """
        if not self.attack_data:
            return
        
        for obj in self.attack_data['objects']:
            if obj['type'] == 'attack-pattern':
                technique_id = obj.get('external_references', [{}])[0].get('external_id', '')
                technique_name = obj.get('name', '')
                
                # Map techniques to tactics
                kill_chain_phases = obj.get('kill_chain_phases', [])
                for phase in kill_chain_phases:
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        tactic = phase.get('phase_name', '')
                        self.techniques_by_tactic[tactic].append({
                            'id': technique_id,
                            'name': technique_name,
                            'description': obj.get('description', '')
                        })
    
    def map_iocs_to_attack_techniques(self, ioc_analysis_results):
        """
        Map IOCs and behaviors to MITRE ATT&CK techniques
        """
        attack_mapping = {
            'identified_techniques': [],
            'tactic_coverage': {},
            'technique_confidence': {},
            'attack_timeline': [],
            'adversary_simulation': {}
        }
        
        # Analyze IOCs for ATT&CK technique indicators
        for ioc, enrichment in ioc_analysis_results.items():
            technique_indicators = self.identify_attack_techniques(ioc, enrichment)
            attack_mapping['identified_techniques'].extend(technique_indicators)
        
        # Calculate tactic coverage
        tactic_coverage = self.calculate_tactic_coverage(attack_mapping['identified_techniques'])
        attack_mapping['tactic_coverage'] = tactic_coverage
        
        # Generate attack timeline
        attack_timeline = self.generate_attack_timeline(attack_mapping['identified_techniques'])
        attack_mapping['attack_timeline'] = attack_timeline
        
        return attack_mapping
    
    def identify_attack_techniques(self, ioc, enrichment_data):
        """
        Identify MITRE ATT&CK techniques based on IOC analysis
        """
        identified_techniques = []
        
        ioc_type = enrichment_data.get('type', '')
        threat_associations = enrichment_data.get('threat_associations', [])
        
        # Map based on IOC type
        if ioc_type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
            # File-based techniques
            identified_techniques.extend([
                {'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'confidence': 0.6},
                {'id': 'T1055', 'name': 'Process Injection', 'confidence': 0.5},
                {'id': 'T1027', 'name': 'Obfuscated Files or Information', 'confidence': 0.7}
            ])
        
        elif ioc_type == 'ip_address':
            # Network-based techniques
            identified_techniques.extend([
                {'id': 'T1071', 'name': 'Application Layer Protocol', 'confidence': 0.8},
                {'id': 'T1095', 'name': 'Non-Application Layer Protocol', 'confidence': 0.6},
                {'id': 'T1041', 'name': 'Exfiltration Over C2 Channel', 'confidence': 0.7}
            ])
        
        elif ioc_type == 'domain':
            # Domain-based techniques
            identified_techniques.extend([
                {'id': 'T1071.001', 'name': 'Web Protocols', 'confidence': 0.8},
                {'id': 'T1568', 'name': 'Dynamic Resolution', 'confidence': 0.6},
                {'id': 'T1102', 'name': 'Web Service', 'confidence': 0.5}
            ])
        
        # Enhance based on threat associations
        for association in threat_associations:
            malware_family = association.get('malware_family', '')
            if malware_family:
                family_techniques = self.get_malware_family_techniques(malware_family)
                identified_techniques.extend(family_techniques)
        
        return identified_techniques
    
    def generate_attack_navigator_layer(self, attack_mapping):
        """
        Generate MITRE ATT&CK Navigator layer for visualization
        """
        navigator_layer = {
            'version': '4.3',
            'name': 'Threat Intelligence Analysis',
            'description': 'ATT&CK techniques identified from threat intelligence analysis',
            'domain': 'enterprise-attack',
            'techniques': []
        }
        
        # Add identified techniques to navigator layer
        for technique in attack_mapping.get('identified_techniques', []):
            technique_entry = {
                'techniqueID': technique['id'],
                'score': technique.get('confidence', 0.5),
                'color': self.get_confidence_color(technique.get('confidence', 0.5)),
                'comment': f"Confidence: {technique.get('confidence', 0.5):.2f}",
                'enabled': True,
                'metadata': []
            }
            navigator_layer['techniques'].append(technique_entry)
        
        return navigator_layer
    
    def get_confidence_color(self, confidence):
        """
        Get color coding based on confidence level
        """
        if confidence >= 0.8:
            return '#d62728'  # Red - High confidence
        elif confidence >= 0.6:
            return '#ff7f0e'  # Orange - Medium confidence
        elif confidence >= 0.4:
            return '#ffbb78'  # Light orange - Low confidence
        else:
            return '#c7c7c7'  # Gray - Very low confidence
\`\`\`

## Quality Assurance and Intelligence Validation

### Intelligence Quality Framework
\`\`\`python
class ThreatIntelligenceQuality:
    def __init__(self):
        self.quality_dimensions = {
            'accuracy': 'Correctness of the intelligence',
            'completeness': 'Comprehensiveness of the intelligence',
            'timeliness': 'Currency and freshness of the intelligence',
            'relevance': 'Applicability to intelligence requirements',
            'reliability': 'Trustworthiness of the source',
            'confidence': 'Degree of certainty in the assessment'
        }
        
        self.confidence_levels = {
            'high': 'Confirmed by multiple independent sources',
            'medium': 'Supported by limited sources',
            'low': 'Single source or uncorroborated',
            'unknown': 'Insufficient information to assess'
        }
    
    def assess_intelligence_quality(self, intelligence_report):
        """
        Assess the quality of threat intelligence report
        """
        quality_assessment = {
            'overall_score': 0,
            'dimension_scores': {},
            'quality_indicators': {},
            'improvement_recommendations': [],
            'confidence_assessment': {}
        }
        
        # Assess each quality dimension
        for dimension, description in self.quality_dimensions.items():
            score = self.assess_quality_dimension(intelligence_report, dimension)
            quality_assessment['dimension_scores'][dimension] = score
        
        # Calculate overall quality score
        overall_score = sum(quality_assessment['dimension_scores'].values()) / len(quality_assessment['dimension_scores'])
        quality_assessment['overall_score'] = overall_score
        
        # Generate improvement recommendations
        recommendations = self.generate_quality_improvements(quality_assessment['dimension_scores'])
        quality_assessment['improvement_recommendations'] = recommendations
        
        return quality_assessment
    
    def assess_quality_dimension(self, intelligence_report, dimension):
        """
        Assess specific quality dimension
        """
        assessment_methods = {
            'accuracy': self.assess_accuracy,
            'completeness': self.assess_completeness,
            'timeliness': self.assess_timeliness,
            'relevance': self.assess_relevance,
            'reliability': self.assess_reliability,
            'confidence': self.assess_confidence
        }
        
        method = assessment_methods.get(dimension)
        if method:
            return method(intelligence_report)
        else:
            return 0.5  # Default neutral score
    
    def assess_accuracy(self, intelligence_report):
        """
        Assess accuracy of intelligence information
        """
        accuracy_indicators = {
            'source_verification': self.check_source_verification(intelligence_report),
            'cross_validation': self.check_cross_validation(intelligence_report),
            'technical_validation': self.check_technical_validation(intelligence_report),
            'historical_accuracy': self.check_historical_accuracy(intelligence_report)
        }
        
        accuracy_score = sum(accuracy_indicators.values()) / len(accuracy_indicators)
        return accuracy_score
    
    def assess_completeness(self, intelligence_report):
        """
        Assess completeness of intelligence coverage
        """
        completeness_factors = {
            'requirement_coverage': self.check_requirement_coverage(intelligence_report),
            'context_provision': self.check_context_provision(intelligence_report),
            'attribution_completeness': self.check_attribution_completeness(intelligence_report),
            'timeline_completeness': self.check_timeline_completeness(intelligence_report)
        }
        
        completeness_score = sum(completeness_factors.values()) / len(completeness_factors)
        return completeness_score
\`\`\`

## Quality Assurance Checklist

### Pre-Analysis Planning
- [ ] Define threat intelligence requirements (PIRs and SIRs)
- [ ] Establish collection sources and access credentials
- [ ] Set up secure analysis environment
- [ ] Prepare threat intelligence platforms and tools
- [ ] Review legal and ethical guidelines for intelligence gathering

### During Analysis
- [ ] Document all data sources and collection timestamps
- [ ] Cross-verify IOCs across multiple threat intelligence feeds
- [ ] Maintain chain of custody for all intelligence artifacts
- [ ] Apply MITRE ATT&CK framework for technique mapping
- [ ] Validate technical indicators through multiple sources

### Post-Analysis Validation
- [ ] Assess confidence levels for all intelligence assessments
- [ ] Cross-reference findings with historical threat data
- [ ] Validate attribution claims through multiple evidence sources
- [ ] Generate actionable intelligence products
- [ ] Archive intelligence data with appropriate classification

### Intelligence Dissemination
- [ ] Tailor intelligence products to audience requirements
- [ ] Apply appropriate handling caveats and classifications
- [ ] Ensure timely delivery to stakeholders
- [ ] Collect feedback for intelligence requirement refinement
- [ ] Track intelligence product usage and effectiveness

This comprehensive Threat Intelligence & IOC Analysis guide provides advanced frameworks for collecting, analyzing, and operationalizing threat intelligence data, with practical techniques for professional threat hunters and security analysts.`,
          prerequisites: [
            'Understanding of cybersecurity threats and attack vectors',
            'Familiarity with MITRE ATT&CK framework',
            'Knowledge of malware analysis fundamentals',
            'Python programming skills for automation',
            'Experience with threat intelligence platforms'
          ],
          expectedOutcomes: [
            'Conduct comprehensive IOC analysis and enrichment',
            'Implement YARA-based threat hunting capabilities',
            'Perform threat actor attribution analysis',
            'Map threats to MITRE ATT&CK framework',
            'Generate high-quality threat intelligence reports'
          ],
          qaSteps: [
            {
              step: 'IOC Validation and Enrichment',
              expectedResult: 'All IOCs validated and enriched with threat intelligence',
              troubleshooting: 'If enrichment fails, verify API access and try alternative sources'
            },
            {
              step: 'MITRE ATT&CK Mapping Verification',
              expectedResult: 'Accurate mapping of observed behaviors to ATT&CK techniques',
              troubleshooting: 'Review technique definitions if mapping seems inaccurate'
            },
            {
              step: 'Attribution Confidence Assessment',
              expectedResult: 'Confident attribution supported by multiple evidence types',
              troubleshooting: 'If confidence is low, gather additional technical and behavioral evidence'
            }
          ],
          troubleshootingTips: [
            'If IOC lookups return no results, the indicator may be new or very targeted',
            'For attribution challenges, focus on technical indicators over public reporting',
            'When YARA rules produce false positives, refine rule conditions for specificity',
            'If threat intelligence feeds are inconsistent, prioritize authoritative sources'
          ],
          tags: ['Threat Intelligence', 'IOC Analysis', 'MITRE ATT&CK', 'Attribution', 'YARA'],
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
    },
    {
      id: 'backend-development',
      title: 'Backend Development',
      description: 'Comprehensive guide for backend developers working on the security platform',
      icon: Code,
      badge: 'Developer Focus',
      items: [
        {
          id: 'backend-architecture',
          title: 'Backend Architecture & Development Guide',
          description: 'Complete technical documentation for backend developers working on the security platform',
          type: 'guide',
          difficulty: 'advanced',
          estimatedTime: '2 hours',
          content: `# Backend Development Guide

## Architecture Overview

### Technology Stack
- **Backend Framework**: FastAPI (Python 3.11+)
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Message Queue**: Redis for caching and pub/sub
- **Container**: Docker with Kubernetes deployment
- **Authentication**: JWT with role-based access control
- **API Documentation**: Auto-generated OpenAPI/Swagger

### System Architecture
\`\`\`
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │────│   FastAPI       │────│   PostgreSQL    │
│   React/TS      │    │   Backend       │    │   Database      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Security      │
                       │   Services      │
                       │ Wazuh/GVM/ZAP   │
                       └─────────────────┘
\`\`\`

## Development Environment Setup

### Prerequisites
\`\`\`bash
# Python 3.11+ with pip
python --version

# PostgreSQL 14+
psql --version

# Redis 6+
redis-cli --version

# Docker & Docker Compose
docker --version
docker-compose --version
\`\`\`

### Local Development Setup
\`\`\`bash
# Clone and setup backend
git clone [repository-url]
cd security-platform-backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\\Scripts\\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Setup environment variables
cp .env.example .env
# Edit .env with your configurations

# Run database migrations
alembic upgrade head

# Start development server
uvicorn app.main:app --reload --port 8000
\`\`\`

## Project Structure

\`\`\`
app/
├── api/
│   └── v1/
│       ├── auth.py          # Authentication endpoints
│       ├── security.py      # Security service endpoints
│       ├── scans.py         # Scan management
│       ├── reports.py       # Report generation
│       └── websocket.py     # WebSocket connections
├── core/
│   ├── config.py           # Configuration management
│   ├── database.py         # Database connection
│   ├── security.py         # Security utilities
│   └── logging.py          # Logging configuration
├── models/
│   ├── user.py            # User data models
│   ├── security.py        # Security data models
│   └── scan.py            # Scan data models
├── schemas/
│   ├── user.py            # Pydantic schemas
│   ├── security.py        # API request/response schemas
│   └── scan.py            # Scan schemas
├── services/
│   ├── auth_service.py    # Authentication logic
│   ├── wazuh_service.py   # Wazuh integration
│   ├── gvm_service.py     # GVM integration
│   └── zap_service.py     # OWASP ZAP integration
└── main.py                # FastAPI application entry
\`\`\`

## Core Components

### 1. Configuration Management
\`\`\`python
# app/core/config.py
from pydantic import BaseSettings

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql://user:pass@localhost/db"
    
    # Security Services
    WAZUH_URL: str = "https://wazuh:55000"
    WAZUH_USER: str = "wazuh"
    WAZUH_PASSWORD: str = "wazuh"
    
    GVM_URL: str = "https://gvm:9390"
    ZAP_URL: str = "http://zap:8080"
    
    # Authentication
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    class Config:
        env_file = ".env"

settings = Settings()
\`\`\`

### 2. Database Models
\`\`\`python
# app/models/security.py
from sqlalchemy import Column, Integer, String, DateTime, Text, Enum
from app.core.database import Base

class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    source = Column(Enum('wazuh', 'gvm', 'zap', name='source_enum'))
    severity = Column(Enum('critical', 'high', 'medium', 'low', name='severity_enum'))
    title = Column(String(255), nullable=False)
    description = Column(Text)
    timestamp = Column(DateTime)
    acknowledged = Column(Boolean, default=False)
\`\`\`

### 3. API Schemas
\`\`\`python
# app/schemas/security.py
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class AlertBase(BaseModel):
    title: str
    description: str
    severity: str
    source: str

class AlertCreate(AlertBase):
    pass

class Alert(AlertBase):
    id: int
    timestamp: datetime
    acknowledged: bool
    
    class Config:
        orm_mode = True
\`\`\`

## Security Service Integration

### Abstract Service Base
\`\`\`python
# app/services/base_service.py
from abc import ABC, abstractmethod
import httpx
from typing import Dict, Any

class SecurityServiceBase(ABC):
    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout)
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        pass
    
    async def make_request(self, method: str, endpoint: str, **kwargs):
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            response = await self.client.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            raise Exception(f"Request failed: {e}")
\`\`\`

### Wazuh Service Implementation
\`\`\`python
# app/services/wazuh_service.py
from .base_service import SecurityServiceBase
from typing import List, Dict, Any

class WazuhService(SecurityServiceBase):
    def __init__(self):
        super().__init__(settings.WAZUH_URL)
        self.auth_token = None
    
    async def authenticate(self):
        auth_data = {
            "user": settings.WAZUH_USER,
            "password": settings.WAZUH_PASSWORD
        }
        response = await self.make_request("POST", "/security/user/authenticate", json=auth_data)
        self.auth_token = response["data"]["token"]
    
    async def health_check(self) -> Dict[str, Any]:
        try:
            if not self.auth_token:
                await self.authenticate()
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            response = await self.make_request("GET", "/", headers=headers)
            return {"status": "healthy", "version": response.get("data", {}).get("api_version")}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    async def get_agents(self) -> List[Dict[str, Any]]:
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        response = await self.make_request("GET", "/agents", headers=headers)
        return response["data"]["affected_items"]
\`\`\`

## API Endpoints

### Security Endpoints
\`\`\`python
# app/api/v1/security.py
from fastapi import APIRouter, Depends, HTTPException
from app.services.wazuh_service import WazuhService
from app.schemas.security import Alert

router = APIRouter()

@router.get("/health")
async def security_health():
    wazuh = WazuhService()
    gvm = GVMService()
    zap = ZAPService()
    
    health_status = {
        "wazuh": await wazuh.health_check(),
        "gvm": await gvm.health_check(),
        "zap": await zap.health_check()
    }
    
    return health_status

@router.get("/alerts", response_model=List[Alert])
async def get_alerts():
    wazuh = WazuhService()
    alerts = await wazuh.get_alerts()
    return alerts
\`\`\`

## WebSocket Implementation

### Connection Manager
\`\`\`python
# app/api/v1/websocket.py
from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, List
import json

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)
    
    def disconnect(self, websocket: WebSocket, user_id: str):
        if user_id in self.active_connections:
            self.active_connections[user_id].remove(websocket)
    
    async def broadcast_to_user(self, message: dict, user_id: str):
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                await connection.send_text(json.dumps(message))

manager = ConnectionManager()

@router.websocket("/security-alerts")
async def websocket_endpoint(websocket: WebSocket, token: str):
    # Verify token and extract user_id
    user_id = verify_token(token)
    
    await manager.connect(websocket, user_id)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, user_id)
\`\`\`

## Quality Assurance

### Testing Structure
\`\`\`python
# tests/test_security_services.py
import pytest
from app.services.wazuh_service import WazuhService

@pytest.mark.asyncio
async def test_wazuh_health_check():
    service = WazuhService()
    health = await service.health_check()
    assert "status" in health

@pytest.fixture
async def db_session():
    # Setup test database session
    pass

def test_create_alert(db_session):
    # Test alert creation
    pass
\`\`\`

### Code Quality Standards
\`\`\`bash
# Install development dependencies
pip install black flake8 mypy pytest pytest-asyncio

# Code formatting
black app/ tests/

# Linting
flake8 app/ tests/

# Type checking
mypy app/

# Run tests
pytest tests/ -v --cov=app
\`\`\`

## Deployment

### Docker Configuration
\`\`\`dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
\`\`\`

### Kubernetes Deployment
\`\`\`yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: security-backend
  template:
    metadata:
      labels:
        app: security-backend
    spec:
      containers:
      - name: backend
        image: security-backend:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: url
\`\`\`

## Modular Development Guidelines

### Service Pattern
- Each external service (Wazuh, GVM, ZAP) has its own service class
- Services inherit from SecurityServiceBase for consistency
- Circuit breaker pattern for resilience

### Database Patterns
- Repository pattern for data access
- Alembic migrations for schema changes
- Connection pooling for performance

### API Design
- RESTful endpoints with proper HTTP methods
- Consistent error handling and responses
- OpenAPI documentation auto-generation

### Security Best Practices
- Input validation with Pydantic schemas
- SQL injection prevention with ORM
- JWT token validation and refresh
- Rate limiting on sensitive endpoints

## Monitoring & Logging

### Structured Logging
\`\`\`python
import structlog

logger = structlog.get_logger()

# In service methods
logger.info("wazuh_api_call", 
           endpoint="/agents", 
           response_time=0.250,
           status_code=200)
\`\`\`

### Health Checks
- Service health endpoints for each integration
- Database connection monitoring  
- Redis connection validation
- Kubernetes readiness/liveness probes`,
          prerequisites: ['Python 3.11+', 'FastAPI experience', 'PostgreSQL knowledge', 'Docker/K8s familiarity'],
          expectedOutcomes: [
            'Set up complete development environment',
            'Understand system architecture and patterns',
            'Implement secure API endpoints',
            'Deploy services to Kubernetes'
          ],
          troubleshootingTips: [
            'Use Docker Compose for local development dependencies',
            'Check service health endpoints before debugging integration issues',
            'Use Alembic for all database schema changes',
            'Implement proper error handling and logging for all external service calls'
          ],
          tags: ['Backend', 'FastAPI', 'Security', 'PostgreSQL', 'Kubernetes', 'Development'],
          lastUpdated: '2024-08-30'
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