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
  BookmarkCheck,
  ChevronRight,
  ChevronDown,
  Filter,
  Home,
  FolderOpen,
  FileText
} from 'lucide-react';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';

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
  const [expandedSections, setExpandedSections] = useState<string[]>(['getting-started']);
  const [filterType, setFilterType] = useState<string>('all');
  const [filterDifficulty, setFilterDifficulty] = useState<string>('all');

  // Comprehensive documentation sections with same content as before
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
      description: 'Open Source Intelligence gathering techniques',
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

### Legal & Ethical Considerations
- **GDPR Compliance**: Data protection regulations
- **Terms of Service**: Respect platform policies
- **Attribution**: Proper source citation
- **Privacy Protection**: Minimize personal data exposure`,
          prerequisites: ['Basic OSINT knowledge', 'Understanding of legal frameworks'],
          expectedOutcomes: [
            'Master professional OSINT methodology',
            'Implement quality assurance processes',
            'Ensure legal and ethical compliance',
            'Produce high-quality intelligence reports'
          ]
        }
      ]
    },
    {
      id: 'penetration-testing',
      title: 'Penetration Testing',
      description: 'Comprehensive penetration testing methodologies',
      icon: Target,
      badge: 'Core',
      items: [
        {
          id: 'pentest-methodology',
          title: 'Penetration Testing Methodology',
          description: 'OWASP and NIST-based penetration testing framework',
          type: 'guide',
          difficulty: 'advanced',
          estimatedTime: '60 minutes',
          content: `# Penetration Testing Methodology

## PTES (Penetration Testing Execution Standard)

### 1. Pre-engagement Interactions
- **Scope Definition**: Clear boundaries and objectives
- **Rules of Engagement**: Authorized activities and limitations
- **Legal Agreements**: Contracts and liability protection
- **Communication Plan**: Reporting structure and escalation

### 2. Intelligence Gathering
- **Passive Reconnaissance**: OSINT without target interaction
- **Active Reconnaissance**: Direct target engagement
- **Infrastructure Mapping**: Network topology discovery
- **Service Identification**: Running services and versions

### 3. Threat Modeling
- **Attack Surface Analysis**: Entry points identification
- **Vulnerability Assessment**: Weakness discovery
- **Risk Prioritization**: Impact and likelihood scoring
- **Attack Path Planning**: Exploitation strategy

### 4. Vulnerability Analysis
- **Automated Scanning**: Tools-based discovery
- **Manual Testing**: Human verification and validation
- **False Positive Elimination**: Result accuracy
- **Exploitation Feasibility**: Practical attack assessment

### 5. Exploitation
- **Initial Compromise**: Gaining foothold
- **Privilege Escalation**: Expanding access rights
- **Lateral Movement**: Network traversal
- **Persistence**: Maintaining access

### 6. Post Exploitation
- **Data Collection**: Evidence gathering
- **Impact Assessment**: Business risk evaluation
- **Cleanup**: Removing traces and restoring systems
- **Documentation**: Detailed findings recording

### 7. Reporting
- **Executive Summary**: High-level business impact
- **Technical Details**: Vulnerability specifics
- **Remediation Guidance**: Fix recommendations
- **Risk Ratings**: CVSS-based scoring`,
          prerequisites: ['Advanced security knowledge', 'Penetration testing experience'],
          expectedOutcomes: [
            'Understand complete testing methodology',
            'Execute professional penetration tests',
            'Produce comprehensive reports',
            'Maintain ethical and legal compliance'
          ]
        }
      ]
    },
    {
      id: 'vulnerability-management',
      title: 'Vulnerability Management',
      description: 'Comprehensive vulnerability assessment and management',
      icon: Shield,
      badge: 'Critical',
      items: [
        {
          id: 'vuln-scanning',
          title: 'Vulnerability Scanning Best Practices',
          description: 'Professional vulnerability assessment methodologies',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '30 minutes',
          content: `# Vulnerability Scanning Best Practices

## Scanning Strategy

### 1. Asset Discovery
- **Network Discovery**: Identify live hosts and services
- **Service Enumeration**: Catalog running services
- **Asset Classification**: Categorize by business importance
- **Baseline Establishment**: Normal state documentation

### 2. Vulnerability Assessment
- **Authenticated Scans**: Credentialed assessments
- **Unauthenticated Scans**: External perspective
- **Web Application Testing**: OWASP Top 10 coverage
- **Database Security**: SQL injection and config issues

### 3. Risk Analysis
- **CVSS Scoring**: Standardized vulnerability rating
- **Business Context**: Asset importance consideration
- **Threat Intelligence**: Active exploit availability
- **Compensating Controls**: Mitigation factor analysis

### 4. Remediation Planning
- **Priority Matrix**: Risk-based prioritization
- **Patch Management**: Update deployment strategy
- **Configuration Hardening**: Security baseline implementation
- **Workaround Solutions**: Temporary risk mitigation`,
          prerequisites: ['Basic security knowledge', 'Network understanding'],
          expectedOutcomes: [
            'Execute effective vulnerability scans',
            'Analyze and prioritize findings',
            'Develop remediation strategies',
            'Maintain security posture'
          ]
        }
      ]
    },
    {
      id: 'backend-development',
      title: 'Backend Development',
      description: 'Backend architecture and development guides',
      icon: Database,
      badge: 'Developer',
      items: [
        {
          id: 'reporting-system-backend',
          title: 'Reporting System Backend Logic',
          description: 'Complete backend implementation guide for the intelligent reporting system',
          type: 'guide',
          difficulty: 'advanced',
          estimatedTime: '90 minutes',
          content: `# Reporting System Backend Logic Guide

## Overview

The Intelligent Reporting System generates AI-powered security reports tailored to different audiences (executives, technical teams, compliance officers). This guide outlines the backend architecture, data flow, and API design needed to support this functionality.

## Core Components Architecture

### 1. Report Generation Pipeline

\`\`\`
Data Collection → Online Research → Content Adaptation → Report Formatting → Delivery
\`\`\`

### 2. Key Data Structures

#### ReportTemplate
\`\`\`typescript
interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  sections: string[];
  format: 'executive' | 'technical' | 'compliance';
  customizable: boolean;
}
\`\`\`

#### AudienceProfile  
\`\`\`typescript
interface AudienceProfile {
  id: string;
  name: string;
  type: 'executive' | 'technical' | 'compliance' | 'custom';
  description: string;
  focusAreas: string[];
  technicalLevel: 'low' | 'medium' | 'high';
  preferredFormat: string;
}
\`\`\`

#### ReportData
\`\`\`typescript
interface ReportData {
  vulnerabilities: SecurityVulnerability[];
  scanResults: ScanResult[];
  complianceStatus: ComplianceCheck[];
  metrics: SecurityMetrics;
  trends: TrendData[];
  recommendations: Recommendation[];
}
\`\`\`

## Required Backend APIs

### 1. Report Management Endpoints

#### \`POST /api/reports/generate\`
**Purpose**: Initiate report generation process
\`\`\`json
{
  "templateId": "string",
  "audienceId": "string", 
  "title": "string",
  "customInstructions": "string",
  "includeResearch": boolean,
  "researchQuery": "string",
  "llmConfig": {
    "provider": "openai|perplexity",
    "model": "string",
    "temperature": number,
    "maxTokens": number
  }
}
\`\`\`

**Response**: 
\`\`\`json
{
  "jobId": "string",
  "status": "initiated",
  "estimatedCompletion": "ISO8601"
}
\`\`\`

#### \`GET /api/reports/status/{jobId}\`
**Purpose**: Check report generation progress
\`\`\`json
{
  "jobId": "string",
  "status": "initiated|collecting|researching|generating|formatting|completed|failed",
  "progress": number,
  "currentStep": "string",
  "estimatedTimeRemaining": number,
  "error": "string|null"
}
\`\`\`

#### \`GET /api/reports/{jobId}\`
**Purpose**: Retrieve generated report
\`\`\`json
{
  "id": "string",
  "title": "string",
  "content": "string",
  "format": "markdown|html|pdf",
  "metadata": {
    "generatedAt": "ISO8601",
    "template": "string",
    "audience": "string",
    "dataSource": "string[]"
  }
}
\`\`\`

### 2. Data Collection Endpoints

#### \`GET /api/security/data\`
**Purpose**: Aggregate security data for reports
\`\`\`json
{
  "vulnerabilities": [],
  "scanResults": [],
  "complianceStatus": [],
  "metrics": {},
  "timeRange": {
    "start": "ISO8601",
    "end": "ISO8601"
  }
}
\`\`\`

### 3. Research Integration Endpoints

#### \`POST /api/research/query\`
**Purpose**: Conduct online security research
\`\`\`json
{
  "query": "string",
  "sources": ["perplexity", "nvd", "mitre"],
  "maxResults": number
}
\`\`\`

## Backend Logic Implementation

### 1. Report Generation Workflow

\`\`\`python
class ReportGenerationService:
    async def generate_report(self, request: ReportGenerationRequest) -> str:
        """
        Main report generation orchestrator
        """
        job_id = self.create_job(request)
        
        # Step 1: Data Collection (20% progress)
        await self.update_progress(job_id, 20, "Collecting security data")
        report_data = await self.gather_security_data(request.time_range)
        
        # Step 2: Online Research (40% progress) 
        if request.include_research:
            await self.update_progress(job_id, 40, "Conducting research")
            research_data = await self.conduct_research(request.research_query)
            report_data.research = research_data
            
        # Step 3: Content Generation (70% progress)
        await self.update_progress(job_id, 70, "Generating content")
        content = await self.generate_adapted_content(
            report_data, 
            request.template,
            request.audience,
            request.llm_config
        )
        
        # Step 4: Formatting (90% progress)
        await self.update_progress(job_id, 90, "Formatting report")
        formatted_report = await self.format_report(content, request.template)
        
        # Step 5: Complete (100% progress)
        await self.complete_job(job_id, formatted_report)
        return job_id
\`\`\`

### 2. Data Aggregation Logic

\`\`\`python
class SecurityDataAggregator:
    async def gather_security_data(self, time_range: TimeRange) -> ReportData:
        """
        Collect and aggregate security data from various sources
        """
        # Parallel data collection
        vulnerabilities = await self.get_vulnerabilities(time_range)
        scan_results = await self.get_scan_results(time_range)
        compliance_status = await self.get_compliance_status(time_range)
        metrics = await self.calculate_metrics(time_range)
        
        return ReportData(
            vulnerabilities=vulnerabilities,
            scan_results=scan_results,
            compliance_status=compliance_status,
            metrics=metrics
        )
    
    async def get_vulnerabilities(self, time_range: TimeRange) -> List[Vulnerability]:
        """Fetch from vulnerability scanners (OpenVAS, Nessus, etc.)"""
        pass
        
    async def get_scan_results(self, time_range: TimeRange) -> List[ScanResult]:
        """Fetch from various security tools (Nmap, ZAP, etc.)"""
        pass
\`\`\`

### 3. LLM Integration Logic

\`\`\`python
class LLMService:
    async def generate_adapted_content(
        self, 
        data: ReportData, 
        template: ReportTemplate,
        audience: AudienceProfile,
        config: LLMConfig
    ) -> str:
        """
        Generate report content adapted to audience
        """
        system_prompt = self.build_system_prompt(template, audience)
        user_prompt = self.build_data_prompt(data)
        
        if config.provider == "openai":
            return await self.openai_generate(system_prompt, user_prompt, config)
        elif config.provider == "perplexity":
            return await self.perplexity_generate(system_prompt, user_prompt, config)
    
    def build_system_prompt(self, template: ReportTemplate, audience: AudienceProfile) -> str:
        """Build context-aware system prompt"""
        return f"""
        Generate a {template.format} security report for {audience.name}.
        Technical level: {audience.technical_level}
        Focus areas: {', '.join(audience.focus_areas)}
        Required sections: {', '.join(template.sections)}
        """
\`\`\`

### 4. Research Integration

\`\`\`python
class ResearchService:
    async def conduct_research(self, query: str) -> ResearchData:
        """
        Conduct online security research using multiple sources
        """
        # Perplexity API for current threat intelligence
        perplexity_results = await self.perplexity_search(query)
        
        # CVE database lookup
        cve_results = await self.search_cve_database(query)
        
        # MITRE ATT&CK framework mapping
        mitre_results = await self.search_mitre_attack(query)
        
        return ResearchData(
            perplexity=perplexity_results,
            cve=cve_results,
            mitre=mitre_results
        )
\`\`\`

## Database Schema

### Reports Table
\`\`\`sql
CREATE TABLE reports (
    id UUID PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    template_id VARCHAR(100) NOT NULL,
    audience_id VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    metadata JSONB,
    status VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    created_by UUID REFERENCES users(id)
);
\`\`\`

### Report Jobs Table
\`\`\`sql
CREATE TABLE report_jobs (
    id UUID PRIMARY KEY,
    report_id UUID REFERENCES reports(id),
    status VARCHAR(50) NOT NULL,
    progress INTEGER DEFAULT 0,
    current_step VARCHAR(255),
    error_message TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
\`\`\`

## Security Considerations

### 1. API Key Management
- Store LLM API keys encrypted in database
- Use environment variables for service API keys
- Implement key rotation mechanism

### 2. Data Privacy
- Sanitize sensitive data before sending to external LLMs
- Implement data retention policies for generated reports
- Audit trail for report access and generation

### 3. Rate Limiting
- Implement rate limits on report generation endpoints
- Queue system for handling multiple concurrent requests
- Cost monitoring for LLM API usage

## Implementation Checklist

### Phase 1: Core Infrastructure
- [ ] Database schema setup
- [ ] Basic CRUD APIs for templates and audiences
- [ ] Job queue system (Redis/Celery)
- [ ] Progress tracking mechanism

### Phase 2: Data Integration
- [ ] Security data aggregation service
- [ ] Vulnerability scanner integrations
- [ ] Metrics calculation engine
- [ ] Data validation and sanitization

### Phase 3: AI Integration  
- [ ] LLM service abstraction layer
- [ ] OpenAI API integration
- [ ] Perplexity API integration
- [ ] Prompt engineering and optimization

### Phase 4: Research Features
- [ ] Online research service
- [ ] CVE database integration
- [ ] MITRE ATT&CK integration
- [ ] Research result caching

### Phase 5: Advanced Features
- [ ] Report scheduling and automation
- [ ] Email delivery system
- [ ] PDF generation service
- [ ] Report analytics and insights

## Error Handling Patterns

\`\`\`python
class ReportGenerationError(Exception):
    """Base exception for report generation errors"""
    pass

class DataCollectionError(ReportGenerationError):
    """Error during security data collection"""
    pass

class LLMGenerationError(ReportGenerationError):
    """Error during LLM content generation"""
    pass

# Error handling in service
try:
    report_data = await self.gather_security_data(time_range)
except DataCollectionError as e:
    await self.fail_job(job_id, f"Data collection failed: {str(e)}")
    raise
\`\`\`

## Monitoring and Observability

### Key Metrics to Track
- Report generation success/failure rates
- Average generation time per report type
- LLM API usage and costs
- Data source availability and response times
- User engagement with generated reports

### Logging Strategy
- Structured logging with correlation IDs
- Performance metrics at each pipeline stage
- Error details with context for debugging
- Audit logs for compliance tracking

## Testing Strategy

### Unit Tests
- Individual service method testing
- Mock external API dependencies
- Data aggregation logic validation

### Integration Tests  
- End-to-end report generation flow
- External API integration testing
- Database transaction testing

### Performance Tests
- Load testing for concurrent report generation
- LLM API response time benchmarking
- Data aggregation performance under scale

This documentation provides the foundation for implementing a robust, scalable reporting system backend that can handle complex security report generation with AI assistance.`,
          prerequisites: [
            'Advanced Python/FastAPI knowledge',
            'Database design experience',
            'API design principles',
            'AI/LLM integration experience',
            'Security domain knowledge'
          ],
          expectedOutcomes: [
            'Understand complete reporting system architecture',
            'Implement scalable backend services',
            'Integrate with multiple LLM providers',
            'Build secure and performant APIs',
            'Deploy production-ready reporting system'
          ],
          tags: ['backend', 'api', 'llm', 'reporting', 'architecture']
        }
      ]
    },
    {
      id: 'security-operations',
      title: 'Security Operations',
      description: 'Production security workflows and automation',
      icon: Shield,
      badge: 'Production',
      items: [
        {
          id: 'ticketing-attack-plans',
          title: 'Ticketing System & Attack Plans',
          description: 'Complete guide to automated security operations, ticketing integration, and continuous vulnerability management',
          type: 'guide',
          difficulty: 'intermediate',
          estimatedTime: '45 minutes',
          content: `# Ticketing System & Attack Plans Guide

## Overview

The Production Security Center implements a continuous **Find-Fix-Verify** security operations model through automated attack plans and integrated ticketing systems. This creates a seamless workflow where security vulnerabilities are automatically discovered, tracked, remediated, and verified.

## Attack Plans Architecture

### What Are Attack Plans?

Attack Plans are **automated, scheduled security assessments** that continuously monitor your infrastructure for vulnerabilities. Think of them as your security team's automated assistants that never sleep.

### Core Components

#### 1. **Automated Scanning Engine**
\`\`\`typescript
interface AttackPlan {
  id: string;
  name: string;                    // e.g., "Daily Web App Scan"
  description: string;             // What this plan does  
  schedule: 'daily' | 'weekly' | 'monthly' | 'custom';
  enabled: boolean;                // Can be toggled on/off
  status: 'idle' | 'running' | 'completed' | 'failed';
  categories: string[];            // e.g., ['web-application', 'owasp-top10']
  targets: string[];               // e.g., ['app.company.com', 'api.company.com']
  lastRun?: Date;
  nextRun?: Date;
}
\`\`\`

#### 2. **Pre-configured Attack Categories**
- **Web Application Security**: OWASP Top 10, SQL injection, XSS, authentication bypass
- **API Security**: REST/GraphQL testing, authentication flaws, business logic errors
- **Infrastructure Security**: Network scanning, port enumeration, service discovery
- **Cloud Security**: AWS/Azure/GCP misconfigurations, IAM assessment, container security

#### 3. **Scheduling System**
- **Daily**: Critical assets scanned every 24 hours
- **Weekly**: Comprehensive infrastructure audits
- **Monthly**: Deep-dive assessments and compliance checks
- **Custom**: User-defined intervals and time windows

## Ticketing System Integration

### Automated Vulnerability-to-Ticket Pipeline

When an attack plan discovers a vulnerability, the system automatically:

1. **Analyzes** the finding (severity, impact, exploitability)
2. **Creates** a structured ticket in your chosen system
3. **Assigns** based on predefined rules
4. **Tracks** remediation progress
5. **Verifies** fixes through re-testing

### Supported Ticketing Systems

#### Jira Integration
\`\`\`json
{
  "provider": "jira",
  "apiUrl": "https://company.atlassian.net",
  "credentials": {
    "username": "security@company.com",
    "token": "ATATT3xFfGF0..."
  },
  "projectKey": "SEC",
  "issueType": "Security Bug",
  "priority": "High"
}
\`\`\`

#### ServiceNow Integration  
\`\`\`json
{
  "provider": "servicenow",
  "apiUrl": "https://company.service-now.com",
  "credentials": {
    "username": "api_user",
    "token": "abc123..."
  },
  "table": "incident",
  "category": "Security",
  "priority": "1 - Critical"
}
\`\`\`

#### Custom API Integration
\`\`\`json
{
  "provider": "custom",
  "apiUrl": "https://your-ticketing-api.com/tickets",
  "headers": {
    "Authorization": "Bearer token",
    "Content-Type": "application/json"
  },
  "mapping": {
    "title": "vulnerability.title",
    "description": "vulnerability.description",
    "severity": "vulnerability.cvss_score"
  }
}
\`\`\`

## Ticket Structure & Format

### Standard Ticket Fields

Every automatically generated ticket contains:

\`\`\`typescript
interface SecurityTicket {
  // Identification
  ticketId: string;                // "SEC-123"
  vulnerabilityId: string;         // "CVE-2024-0001" or internal ID
  
  // Content
  title: string;                   // "SQL Injection in Login Form"
  description: string;             // Detailed vulnerability information
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  
  // Classification
  category: string;                // "Web Application", "Network", etc.
  cweId?: string;                  // CWE-89 (SQL Injection)
  cvssScore?: number;              // 9.1
  
  // Location
  affectedAssets: string[];        // ["app.company.com", "api.company.com"]
  url?: string;                    // Specific endpoint if applicable
  
  // Remediation
  recommendedActions: string[];    // Step-by-step fix instructions
  references: string[];            // Links to documentation, patches
  
  // Workflow
  assignedTo: string;              // Team or individual
  priority: string;                // Based on business impact
  labels: string[];                // For categorization and filtering
}
\`\`\`

### Example Generated Ticket

\`\`\`markdown
**Title**: Critical SQL Injection Vulnerability in User Authentication

**Description**: 
A SQL injection vulnerability was discovered in the user login endpoint that allows attackers to bypass authentication and potentially access sensitive user data.

**Technical Details**:
- **Endpoint**: https://app.company.com/api/login
- **Parameter**: username (POST body)
- **Attack Vector**: \`admin' OR '1'='1' --\`
- **CVSS Score**: 9.1 (Critical)
- **CWE**: CWE-89 (SQL Injection)

**Impact**:
- Authentication bypass
- Potential data exfiltration
- Database manipulation possible

**Remediation Steps**:
1. Implement parameterized queries/prepared statements
2. Add input validation and sanitization
3. Apply principle of least privilege to database user
4. Enable SQL query logging for monitoring

**References**:
- OWASP SQL Injection Prevention: https://owasp.org/www-project-top-ten/2017/A1_2017-Injection
- Fix Examples: [Internal KB Link]

**Verification**:
- [ ] Code review completed
- [ ] Automated retest passed
- [ ] Penetration test verification
\`\`\`

## Remediation Tracking Workflow

### Lifecycle States

\`\`\`typescript
interface RemediationTracking {
  ticketId: string;
  vulnerabilityId: string;
  status: 'open' | 'in_progress' | 'resolved' | 'verified' | 'reopened';
  assignedTo: string;
  createdAt: Date;
  updatedAt: Date;
  verificationAttempts: number;
  autoRetest: boolean;
  retestSchedule?: Date;
}
\`\`\`

### State Transitions

1. **Open**: Vulnerability discovered, ticket created
2. **In Progress**: Developer/team assigned and working on fix
3. **Resolved**: Fix implemented, ready for verification
4. **Verified**: Automated retest confirms vulnerability is fixed
5. **Reopened**: Retest failed, vulnerability still present

## Configuration Best Practices

### Attack Plan Strategy

#### High-Value Targets (Daily Scans)
\`\`\`javascript
const criticalAssets = [
  'app.company.com',      // Customer-facing application
  'api.company.com',      // Public API endpoints  
  'admin.company.com',    // Administrative interfaces
  'payment.company.com'   // Payment processing
];
\`\`\`

#### Infrastructure Assessment (Weekly)
\`\`\`javascript
const infrastructureTargets = [
  '10.0.0.0/24',         // Internal network ranges
  'vpn.company.com',     // VPN endpoints
  'mail.company.com',    // Email infrastructure
  'dns1.company.com'     // DNS servers
];
\`\`\`

### Ticketing Configuration

#### Auto-Assignment Rules
\`\`\`json
{
  "assignment_rules": [
    {
      "condition": "category == 'Web Application'",
      "assignee": "web-dev-team",
      "cc": ["security-team"]
    },
    {
      "condition": "severity == 'Critical'",
      "assignee": "security-incident-team",
      "priority": "Immediate"
    },
    {
      "condition": "cvss_score >= 7.0",
      "assignee": "senior-developer",
      "labels": ["high-risk", "security"]
    }
  ]
}
\`\`\`

## Metrics and Reporting

### Key Performance Indicators

#### Discovery Metrics
- Vulnerabilities found per scan
- False positive rate
- Coverage metrics (assets scanned vs. total assets)
- Time to discovery (0-day to detection)

#### Response Metrics  
- Mean Time to Acknowledge (MTTA)
- Mean Time to Resolve (MTTR)
- Fix rate percentage
- SLA compliance rate

#### Quality Metrics
- Vulnerability recurrence rate
- Verification success rate
- Escalation frequency
- Team response effectiveness

## Security Considerations

### Data Protection
- **Encryption**: All ticket data encrypted in transit and at rest
- **Access Control**: Role-based access to vulnerability details
- **Audit Logging**: Complete trail of all ticket modifications
- **Data Retention**: Configurable retention policies for compliance

### API Security
- **Authentication**: API tokens with limited scope and expiration
- **Rate Limiting**: Prevent abuse of ticketing APIs
- **IP Whitelisting**: Restrict API access to authorized networks
- **Webhook Verification**: Validate incoming webhook signatures

This system creates a robust, automated security operations pipeline that scales with your organization while maintaining the human oversight needed for effective security management.`,
          prerequisites: [
            'Basic understanding of security operations',
            'Familiarity with ticketing systems (Jira/ServiceNow)',
            'Knowledge of vulnerability management',
            'Understanding of DevSecOps workflows'
          ],
          expectedOutcomes: [
            'Configure automated attack plans effectively',
            'Set up ticketing system integrations',
            'Understand remediation tracking workflows',
            'Implement continuous security operations',
            'Monitor and optimize security processes'
          ],
          tags: ['security-operations', 'ticketing', 'attack-plans', 'automation', 'remediation']
        }
      ]
    }
  ];

  // Helper functions
  const handleSearch = (query: string) => {
    setSearchQuery(query);
    if (query) {
      // Auto-expand sections with matching content
      const matchingSections = documentationSections
        .filter(section => 
          section.title.toLowerCase().includes(query.toLowerCase()) ||
          section.description.toLowerCase().includes(query.toLowerCase()) ||
          section.items.some(item => 
            item.title.toLowerCase().includes(query.toLowerCase()) ||
            item.description.toLowerCase().includes(query.toLowerCase()) ||
            item.content.toLowerCase().includes(query.toLowerCase())
          )
        )
        .map(section => section.id);
      
      setExpandedSections(prev => [...new Set([...prev, ...matchingSections])]);
    }
  };

  const toggleSection = (sectionId: string) => {
    setExpandedSections(prev => 
      prev.includes(sectionId) 
        ? prev.filter(id => id !== sectionId)
        : [...prev, sectionId]
    );
  };

  const toggleBookmark = (docId: string) => {
    setBookmarkedDocs(prev => 
      prev.includes(docId) 
        ? prev.filter(id => id !== docId)
        : [...prev, docId]
    );
    toast({
      title: bookmarkedDocs.includes(docId) ? "Bookmark Removed" : "Bookmark Added",
      description: "Documentation bookmark updated"
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to clipboard",
      description: "Content has been copied successfully"
    });
  };

  // Filter and search logic
  const getFilteredItems = (items: DocItem[]) => {
    return items.filter(item => {
      const matchesSearch = !searchQuery || 
        item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.content.toLowerCase().includes(searchQuery.toLowerCase());
      
      const matchesType = filterType === 'all' || item.type === filterType;
      const matchesDifficulty = filterDifficulty === 'all' || item.difficulty === filterDifficulty;
      
      return matchesSearch && matchesType && matchesDifficulty;
    });
  };

  const selectedDocItem = selectedDoc 
    ? documentationSections.flatMap(s => s.items).find(item => item.id === selectedDoc)
    : null;

  const getBreadcrumbs = () => {
    if (!selectedDoc) return [];
    
    const section = documentationSections.find(s => 
      s.items.some(item => item.id === selectedDoc)
    );
    
    return section ? [section.title, selectedDocItem?.title] : [];
  };

  return (
    <Dialog open onOpenChange={onClose}>
      <DialogContent className="max-w-6xl max-h-[85vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <BookOpen className="h-5 w-5" />
            Documentation Library
            {selectedDoc && (
              <div className="flex items-center text-sm text-muted-foreground ml-4">
                <Home className="h-4 w-4" />
                {getBreadcrumbs().map((crumb, index) => (
                  <React.Fragment key={index}>
                    <ChevronRight className="h-3 w-3 mx-1" />
                    <span>{crumb}</span>
                  </React.Fragment>
                ))}
              </div>
            )}
          </DialogTitle>
        </DialogHeader>

        <div className="flex h-[calc(85vh-6rem)] gap-4">
          {/* Compact Sidebar */}
          <div className="w-72 border-r pr-4 space-y-4">
            {/* Search & Filters */}
            <div className="space-y-2">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search docs..."
                  value={searchQuery}
                  onChange={(e) => handleSearch(e.target.value)}
                  className="pl-10 h-8"
                />
              </div>
              
              <div className="flex gap-2">
                <select 
                  value={filterType}
                  onChange={(e) => setFilterType(e.target.value)}
                  className="flex h-7 rounded-md border border-input bg-background px-2 py-1 text-xs"
                >
                  <option value="all">All Types</option>
                  <option value="guide">Guides</option>
                  <option value="tutorial">Tutorials</option>
                  <option value="reference">Reference</option>
                </select>
                
                <select 
                  value={filterDifficulty}
                  onChange={(e) => setFilterDifficulty(e.target.value)}
                  className="flex h-7 rounded-md border border-input bg-background px-2 py-1 text-xs"
                >
                  <option value="all">All Levels</option>
                  <option value="beginner">Beginner</option>
                  <option value="intermediate">Intermediate</option>
                  <option value="advanced">Advanced</option>
                </select>
              </div>
            </div>

            {/* Navigation Tree */}
            <ScrollArea className="h-full">
              <div className="space-y-1">
                {documentationSections.map((section) => {
                  const filteredItems = getFilteredItems(section.items);
                  if (filteredItems.length === 0 && searchQuery) return null;
                  
                  return (
                    <Collapsible
                      key={section.id}
                      open={expandedSections.includes(section.id)}
                      onOpenChange={() => toggleSection(section.id)}
                    >
                      <CollapsibleTrigger asChild>
                        <Button
                          variant="ghost"
                          className="w-full justify-between p-2 h-auto text-left hover:bg-muted/50"
                        >
                          <div className="flex items-center gap-2">
                            <section.icon className="h-4 w-4" />
                            <div className="flex-1">
                              <div className="font-medium text-sm">{section.title}</div>
                              <div className="text-xs text-muted-foreground">
                                {filteredItems.length} items
                              </div>
                            </div>
                            {section.badge && (
                              <Badge variant="secondary" className="text-xs">
                                {section.badge}
                              </Badge>
                            )}
                          </div>
                          {expandedSections.includes(section.id) ? (
                            <ChevronDown className="h-4 w-4" />
                          ) : (
                            <ChevronRight className="h-4 w-4" />
                          )}
                        </Button>
                      </CollapsibleTrigger>
                      
                      <CollapsibleContent className="space-y-1 ml-6">
                        {filteredItems.map((item) => (
                          <Button
                            key={item.id}
                            variant={selectedDoc === item.id ? "secondary" : "ghost"}
                            className="w-full justify-start p-2 h-auto text-left"
                            onClick={() => setSelectedDoc(item.id)}
                          >
                            <div className="flex items-center gap-2 w-full">
                              <FileText className="h-3 w-3" />
                              <div className="flex-1 min-w-0">
                                <div className="font-medium text-xs truncate">{item.title}</div>
                                <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                  <Badge variant="outline" className="text-xs px-1 py-0">
                                    {item.type}
                                  </Badge>
                                  <Badge variant="outline" className="text-xs px-1 py-0">
                                    {item.difficulty}
                                  </Badge>
                                </div>
                              </div>
                              {bookmarkedDocs.includes(item.id) && (
                                <BookmarkCheck className="h-3 w-3 text-primary" />
                              )}
                            </div>
                          </Button>
                        ))}
                      </CollapsibleContent>
                    </Collapsible>
                  );
                })}
              </div>
            </ScrollArea>
          </div>

          {/* Main Content Area */}
          <div className="flex-1 min-w-0">
            {selectedDoc && selectedDocItem ? (
              /* Document View */
              <div className="h-full flex flex-col">
                {/* Document Header */}
                <div className="flex items-center justify-between mb-4 pb-2 border-b">
                  <div className="flex items-center gap-2 min-w-0">
                    <Button 
                      variant="ghost" 
                      size="sm"
                      onClick={() => setSelectedDoc(null)}
                    >
                      ← Back
                    </Button>
                    <div className="min-w-0">
                      <h2 className="font-semibold text-lg truncate">{selectedDocItem.title}</h2>
                      <p className="text-sm text-muted-foreground">{selectedDocItem.description}</p>
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
                      onClick={() => copyToClipboard(selectedDocItem.content)}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                {/* Document Content Tabs */}
                <div className="flex-1 overflow-hidden">
                  <Tabs defaultValue="content" className="h-full flex flex-col">
                    <TabsList className="grid w-full grid-cols-3">
                      <TabsTrigger value="content">Content</TabsTrigger>
                      <TabsTrigger value="info">Details</TabsTrigger>
                      <TabsTrigger value="qa">QA</TabsTrigger>
                    </TabsList>

                    <TabsContent value="content" className="flex-1 mt-4 overflow-hidden">
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
                                {selectedDocItem.prerequisites.map((prereq, index) => (
                                  <li key={index} className="flex items-start gap-2">
                                    <CheckCircle className="h-3 w-3 text-green-500 mt-0.5" />
                                    {prereq}
                                  </li>
                                ))}
                              </ul>
                            </CardContent>
                          </Card>
                        )}
                      </div>

                      {selectedDocItem.expectedOutcomes && (
                        <Card className="mt-4">
                          <CardHeader>
                            <CardTitle className="text-base">Expected Outcomes</CardTitle>
                          </CardHeader>
                          <CardContent>
                            <ul className="text-sm space-y-1">
                              {selectedDocItem.expectedOutcomes.map((outcome, index) => (
                                <li key={index} className="flex items-start gap-2">
                                  <Star className="h-3 w-3 text-yellow-500 mt-0.5" />
                                  {outcome}
                                </li>
                              ))}
                            </ul>
                          </CardContent>
                        </Card>
                      )}
                    </TabsContent>

                    <TabsContent value="qa" className="mt-4">
                      {selectedDocItem.qaSteps ? (
                        <div className="space-y-4">
                          {selectedDocItem.qaSteps.map((step, index) => (
                            <Card key={index}>
                              <CardHeader>
                                <CardTitle className="text-sm">Step {index + 1}: {step.step}</CardTitle>
                              </CardHeader>
                              <CardContent className="space-y-2">
                                <div>
                                  <span className="text-sm font-medium">Expected Result:</span>
                                  <p className="text-sm text-muted-foreground">{step.expectedResult}</p>
                                </div>
                                {step.troubleshooting && (
                                  <div>
                                    <span className="text-sm font-medium">Troubleshooting:</span>
                                    <p className="text-sm text-muted-foreground">{step.troubleshooting}</p>
                                  </div>
                                )}
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      ) : (
                        <Card>
                          <CardContent className="pt-6">
                            <p className="text-muted-foreground text-center">No QA steps defined for this document.</p>
                          </CardContent>
                        </Card>
                      )}
                    </TabsContent>
                  </Tabs>
                </div>
              </div>
            ) : (
              /* Overview/Home View */
              <div className="h-full">
                <div className="mb-6">
                  <h2 className="text-2xl font-bold mb-2">Documentation Overview</h2>
                  <p className="text-muted-foreground">
                    Comprehensive guides, tutorials, and references for the IPS Security Center
                  </p>
                </div>

                <ScrollArea className="h-full">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {documentationSections.map((section) => {
                      const filteredItems = getFilteredItems(section.items);
                      if (filteredItems.length === 0 && searchQuery) return null;
                      
                      return (
                        <Card 
                          key={section.id} 
                          className="cursor-pointer hover:bg-muted/50 transition-colors"
                          onClick={() => {
                            setSelectedSection(section.id);
                            if (!expandedSections.includes(section.id)) {
                              toggleSection(section.id);
                            }
                          }}
                        >
                          <CardHeader>
                            <div className="flex items-center gap-3">
                              <section.icon className="h-6 w-6" />
                              <div className="flex-1">
                                <CardTitle className="flex items-center gap-2">
                                  {section.title}
                                  {section.badge && (
                                    <Badge variant="secondary" className="text-xs">
                                      {section.badge}
                                    </Badge>
                                  )}
                                </CardTitle>
                                <CardDescription>{section.description}</CardDescription>
                              </div>
                            </div>
                          </CardHeader>
                          <CardContent>
                            <div className="flex items-center justify-between text-sm">
                              <span className="text-muted-foreground">
                                {filteredItems.length} item{filteredItems.length !== 1 ? 's' : ''}
                              </span>
                              <ChevronRight className="h-4 w-4" />
                            </div>
                          </CardContent>
                        </Card>
                      );
                    })}
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