# Reporting System Backend Logic Guide

## Overview

The Intelligent Reporting System generates AI-powered security reports tailored to different audiences (executives, technical teams, compliance officers). This guide outlines the backend architecture, data flow, and API design needed to support this functionality.

## Core Components Architecture

### 1. Report Generation Pipeline

```
Data Collection → Online Research → Content Adaptation → Report Formatting → Delivery
```

### 2. Key Data Structures

#### ReportTemplate
```typescript
interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  sections: string[];
  format: 'executive' | 'technical' | 'compliance';
  customizable: boolean;
}
```

#### AudienceProfile  
```typescript
interface AudienceProfile {
  id: string;
  name: string;
  type: 'executive' | 'technical' | 'compliance' | 'custom';
  description: string;
  focusAreas: string[];
  technicalLevel: 'low' | 'medium' | 'high';
  preferredFormat: string;
}
```

#### ReportData
```typescript
interface ReportData {
  vulnerabilities: SecurityVulnerability[];
  scanResults: ScanResult[];
  complianceStatus: ComplianceCheck[];
  metrics: SecurityMetrics;
  trends: TrendData[];
  recommendations: Recommendation[];
}
```

## Required Backend APIs

### 1. Report Management Endpoints

#### `POST /api/reports/generate`
**Purpose**: Initiate report generation process
```json
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
```

**Response**: 
```json
{
  "jobId": "string",
  "status": "initiated",
  "estimatedCompletion": "ISO8601"
}
```

#### `GET /api/reports/status/{jobId}`
**Purpose**: Check report generation progress
```json
{
  "jobId": "string",
  "status": "initiated|collecting|researching|generating|formatting|completed|failed",
  "progress": number,
  "currentStep": "string",
  "estimatedTimeRemaining": number,
  "error": "string|null"
}
```

#### `GET /api/reports/{jobId}`
**Purpose**: Retrieve generated report
```json
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
```

### 2. Data Collection Endpoints

#### `GET /api/security/data`
**Purpose**: Aggregate security data for reports
```json
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
```

### 3. Research Integration Endpoints

#### `POST /api/research/query`
**Purpose**: Conduct online security research
```json
{
  "query": "string",
  "sources": ["perplexity", "nvd", "mitre"],
  "maxResults": number
}
```

## Backend Logic Implementation

### 1. Report Generation Workflow

```python
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
```

### 2. Data Aggregation Logic

```python
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
```

### 3. LLM Integration Logic with Prompt Engineering

```python
class LLMService:
    async def generate_adapted_content(
        self, 
        data: ReportData, 
        template: ReportTemplate,
        audience: AudienceProfile,
        config: LLMConfig
    ) -> str:
        """
        Generate report content adapted to audience with optimized prompts
        """
        system_prompt = self.build_system_prompt(template, audience)
        user_prompt = self.build_data_prompt(data, audience)
        
        if config.provider == "openai":
            return await self.openai_generate(system_prompt, user_prompt, config)
        elif config.provider == "perplexity":
            return await self.perplexity_generate(system_prompt, user_prompt, config)
        elif config.provider == "lovable-ai":
            return await self.lovable_ai_generate(system_prompt, user_prompt, config)
    
    def build_system_prompt(self, template: ReportTemplate, audience: AudienceProfile) -> str:
        """Build comprehensive context-aware system prompt"""
        
        # Base prompt foundation
        base_prompt = f"""You are an elite cybersecurity report writer with deep expertise in {audience.name} communication. 
You specialize in translating complex security findings into actionable insights tailored to specific audiences.

TARGET AUDIENCE: {audience.name}
Technical Proficiency: {audience.technical_level}
Primary Focus Areas: {', '.join(audience.focus_areas)}
Preferred Communication Style: {audience.preferred_format}"""

        # Audience-specific guidelines
        audience_guidelines = self.get_audience_guidelines(audience.type)
        
        # Template-specific requirements
        template_requirements = f"""
REPORT TEMPLATE: {template.name}
Report Format: {template.format}
Required Sections: {', '.join(template.sections)}
Description: {template.description}"""

        # Writing standards
        writing_standards = """
WRITING STANDARDS:
- Use clear, professional language appropriate for the target audience
- Provide specific, actionable recommendations with clear priorities
- Include relevant code examples and implementation guidance where appropriate
- Reference current security standards (OWASP, NIST, CIS, etc.)
- Support claims with data and evidence from the security assessment
- Structure content with clear headings and logical flow
- Use bullet points and tables for clarity when presenting complex data
- Maintain consistency in terminology and formatting throughout"""

        return f"{base_prompt}\n\n{audience_guidelines}\n\n{template_requirements}\n\n{writing_standards}"
    
    def get_audience_guidelines(self, audience_type: str) -> str:
        """Return detailed guidelines for each audience type"""
        
        guidelines = {
            "executive": """
EXECUTIVE LEADERSHIP GUIDELINES:
Mindset: Business-focused, risk-aware, ROI-oriented, time-constrained decision-makers
Communication Approach:
  ✓ Lead with business impact and financial implications
  ✓ Use high-level executive summaries (2-3 paragraphs max)
  ✓ Present risk in terms of business continuity and competitive advantage
  ✓ Provide clear prioritized action items with timelines and resource needs
  ✓ Include cost-benefit analysis for major recommendations
  ✗ Avoid technical jargon unless absolutely necessary
  ✗ Don't overwhelm with technical details in main sections
  ✗ Never present findings without business context

Key Sections to Emphasize:
1. Executive Summary (critical risks, business impact, key decisions)
2. Risk Overview (risk levels, exposure areas, potential consequences)
3. Investment Recommendations (costs, benefits, ROI projections)
4. Compliance Status (regulatory implications, audit readiness)
5. Strategic Roadmap (timeline, milestones, success metrics)

Metrics to Highlight:
- Overall risk score and trend
- Compliance percentage against key frameworks
- Estimated cost of inaction vs. remediation
- Time to remediate critical issues
- Impact on business operations

Language Style:
- Concise and confident
- Focus on "what this means for the business"
- Use analogies to explain complex security concepts
- Quantify everything possible (costs, timeframes, risks)""",

            "technical": """
TECHNICAL TEAMS GUIDELINES:
Mindset: Detail-oriented, solution-focused, tool-savvy, implementation-ready engineers
Communication Approach:
  ✓ Provide comprehensive technical details and exact specifications
  ✓ Include CVE identifiers, CVSS scores, and vulnerability classifications
  ✓ Show precise attack vectors and exploitation scenarios
  ✓ Provide step-by-step remediation procedures with code examples
  ✓ Reference specific tools, configurations, and technical standards
  ✓ Include command-line examples, API calls, and configuration samples
  ✗ Don't oversimplify or omit technical details
  ✗ Avoid vague recommendations without implementation specifics

Key Sections to Emphasize:
1. Vulnerability Analysis (detailed findings with technical depth)
2. Attack Vectors (how vulnerabilities can be exploited)
3. Remediation Steps (exact procedures, code fixes, configurations)
4. Code Examples (working samples of secure implementations)
5. Testing & Validation (how to verify fixes are effective)
6. Technical Appendices (detailed scan results, logs, traces)

Metrics to Highlight:
- CVSS scores and severity distributions
- Vulnerability counts by category (OWASP Top 10, CWE)
- False positive rates
- Technical debt quantification
- Remediation complexity scores

Language Style:
- Precise and technical
- Use industry-standard terminology
- Include actual code, commands, and configurations
- Reference specific CVEs, CWEs, and security standards
- Provide working examples that can be copied and used

Code Example Format:
```language
// Bad: Vulnerable code
[show vulnerable implementation]

// Good: Secure alternative  
[show secure implementation with inline comments]

// Why: Explanation of the security improvement
```""",

            "compliance": """
COMPLIANCE & RISK OFFICERS GUIDELINES:
Mindset: Regulation-focused, audit-ready, process-oriented, documentation-heavy professionals
Communication Approach:
  ✓ Map all findings to specific regulatory requirements
  ✓ Provide audit-ready documentation with evidence trails
  ✓ Include policy violation details and compliance gaps
  ✓ Show compliance percentage against relevant frameworks
  ✓ Reference specific regulatory standards and clauses
  ✓ Include timestamps, evidence, and audit trails
  ✗ Don't present findings without regulatory context
  ✗ Avoid informal language or vague compliance statements

Key Sections to Emphasize:
1. Regulatory Status (compliance against all applicable frameworks)
2. Risk Matrix (risk levels mapped to business impact)
3. Policy Violations (specific breaches with evidence)
4. Audit Trail (timeline of findings, actions, resolutions)
5. Action Items (prioritized remediation mapped to regulations)
6. Documentation (evidence, screenshots, logs, timestamps)

Frameworks to Reference:
- SOC 2 (Type I/II)
- ISO 27001/27002
- NIST Cybersecurity Framework
- PCI DSS
- HIPAA/HITECH
- GDPR
- CCPA
- Industry-specific regulations

Metrics to Highlight:
- Compliance percentage per framework
- Number of policy violations by severity
- Audit findings (open, resolved, pending)
- Risk scores by asset category
- Time to remediate compliance gaps

Language Style:
- Formal and regulation-aligned
- Evidence-based and audit-ready
- Reference specific regulatory clauses
- Use compliance terminology consistently
- Provide clear documentation trails

Compliance Mapping Format:
| Finding | Severity | Framework | Requirement | Status | Evidence |
|---------|----------|-----------|-------------|--------|----------|
| [Issue] | [Level]  | [SOC2/etc]| [Control]   | [Open] | [Link]   |""",

            "developer": """
DEVELOPMENT TEAMS GUIDELINES:
Mindset: Code-focused, integration-minded, efficiency-driven, learning-oriented builders
Communication Approach:
  ✓ Focus on code-level vulnerabilities and secure coding practices
  ✓ Provide working code examples for every recommendation
  ✓ Show integration patterns with existing frameworks and tools
  ✓ Include testing procedures and validation steps
  ✓ Reference secure coding standards and best practices
  ✓ Suggest libraries, dependencies, and tools to use
  ✗ Don't just identify problems without providing code solutions
  ✗ Avoid theoretical concepts without practical implementation

Key Sections to Emphasize:
1. Code Vulnerabilities (specific code issues with line numbers)
2. Secure Code Examples (working implementations)
3. Best Practices (coding standards, design patterns)
4. Testing Guidelines (unit tests, integration tests, security tests)
5. Integration Guides (how to integrate security into CI/CD)
6. Dependency Management (library recommendations, version updates)

Topics to Cover:
- Input validation and sanitization
- Authentication and authorization patterns
- Secure data storage and transmission
- API security best practices
- Error handling and logging
- Dependency management and supply chain security
- Security testing automation

Metrics to Highlight:
- Code quality scores
- Security debt quantification
- Fix complexity (effort estimation)
- Test coverage for security issues
- Development impact (time, resources)

Language Style:
- Practical and code-heavy
- Example-driven and tutorial-like
- Use familiar programming terminology
- Include links to documentation and resources
- Explain the "why" behind security practices

Code Example Format:
```language
// ❌ VULNERABLE: Why this is insecure
function processUserInput(input) {
  return eval(input); // Direct eval is dangerous
}

// ✅ SECURE: Safe alternative
function processUserInput(input) {
  // Validate input against whitelist
  const sanitized = validator.escape(input);
  return JSON.parse(sanitized);
}

// 📚 REFERENCE: OWASP Input Validation Cheat Sheet
// 🔧 TESTING: 
describe('processUserInput', () => {
  it('should reject malicious input', () => {
    expect(() => processUserInput('malicious')).toThrow();
  });
});
```"""
        }
        
        return guidelines.get(audience_type, guidelines["technical"])
    
    def build_data_prompt(self, data: ReportData, audience: AudienceProfile) -> str:
        """Build comprehensive data prompt with context"""
        
        return f"""Generate a comprehensive security report based on the following assessment data:

═══════════════════════════════════════════════════════════════
VULNERABILITY SUMMARY
═══════════════════════════════════════════════════════════════

{self.format_vulnerabilities(data.vulnerabilities, audience)}

═══════════════════════════════════════════════════════════════
SCAN RESULTS & FINDINGS
═══════════════════════════════════════════════════════════════

{self.format_scan_results(data.scan_results, audience)}

═══════════════════════════════════════════════════════════════
COMPLIANCE STATUS
═══════════════════════════════════════════════════════════════

{self.format_compliance(data.compliance_status, audience)}

═══════════════════════════════════════════════════════════════
SECURITY METRICS
═══════════════════════════════════════════════════════════════

{self.format_metrics(data.metrics, audience)}

═══════════════════════════════════════════════════════════════
RECOMMENDATIONS
═══════════════════════════════════════════════════════════════

{self.format_recommendations(data.recommendations, audience)}

INSTRUCTIONS:
1. Analyze all provided data comprehensively
2. Adapt the analysis and language specifically for {audience.name}
3. Follow the communication guidelines for this audience type
4. Include relevant code examples and best practices
5. Prioritize recommendations based on risk and impact
6. Ensure all sections are complete and actionable
7. Maintain professional tone appropriate for the audience"""

    def format_vulnerabilities(self, vulnerabilities: List, audience: AudienceProfile) -> str:
        """Format vulnerabilities based on audience needs"""
        if not vulnerabilities:
            return "No critical vulnerabilities detected in the assessment period."
        
        # Different formatting based on audience
        if audience.type == "executive":
            # High-level summary for executives
            critical = sum(1 for v in vulnerabilities if v.severity == "Critical")
            high = sum(1 for v in vulnerabilities if v.severity == "High")
            return f"""
Critical Issues: {critical}
High Priority Issues: {high}
Total Vulnerabilities: {len(vulnerabilities)}

Business Impact: [LLM will expand on business consequences]"""
        
        elif audience.type == "technical":
            # Detailed technical breakdown
            output = []
            for v in vulnerabilities[:10]:  # Show top 10
                output.append(f"""
CVE: {v.id}
Severity: {v.severity} (CVSS: {v.cvss})
Description: {v.description}
Affected Systems: {', '.join(v.affected_systems)}
Attack Vector: {v.attack_vector if hasattr(v, 'attack_vector') else 'N/A'}
""")
            return "\n".join(output)
        
        elif audience.type == "compliance":
            # Compliance-focused view
            output = []
            for v in vulnerabilities:
                frameworks = v.regulatory_impact if hasattr(v, 'regulatory_impact') else []
                output.append(f"""
Finding: {v.id}
Severity: {v.severity}
Regulatory Impact: {', '.join(frameworks) if frameworks else 'General security'}
Compliance Gap: {v.compliance_gap if hasattr(v, 'compliance_gap') else 'Under review'}
""")
            return "\n".join(output)
        
        elif audience.type == "developer":
            # Code-focused view
            output = []
            for v in vulnerabilities[:10]:
                output.append(f"""
Issue: {v.description}
Location: {v.code_location if hasattr(v, 'code_location') else 'System-wide'}
CWE: {v.cwe if hasattr(v, 'cwe') else 'N/A'}
Fix Complexity: {v.fix_complexity if hasattr(v, 'fix_complexity') else 'Medium'}
""")
            return "\n".join(output)
        
        return str(vulnerabilities)
```

### 4. Research Integration

```python
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
```

## Database Schema

### Reports Table
```sql
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
```

### Report Jobs Table
```sql
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
```

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

```python
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
```

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

This documentation provides the foundation for implementing a robust, scalable reporting system backend that can handle complex security report generation with AI assistance.