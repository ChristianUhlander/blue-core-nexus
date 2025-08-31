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

### 3. LLM Integration Logic

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