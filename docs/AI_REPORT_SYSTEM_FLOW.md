# AI Report System - Complete Functionality Flow

## Overview

The AI Report System is an intelligent security reporting platform that generates customized, audience-specific security reports by aggregating data from multiple security tools, enhancing it with online research, and adapting the content using Large Language Models (LLMs).

---

## System Architecture & Data Sources

### 1. Data Collection Layer

The system aggregates security data from multiple integrated sources:

#### Primary Data Sources
- **GVM (Greenbone Vulnerability Management)**: Vulnerability scan results, risk scores, affected assets
- **Wazuh SIEM**: Security events, alerts, agent status, compliance data
- **Wazuh SBOM**: Software Bill of Materials, component vulnerabilities, dependency analysis
- **ZAP Proxy**: Web application security findings, OWASP Top 10 violations
- **Agentic Penetration Testing**: AI-driven pentest results, exploitation attempts, security recommendations

#### Data Aggregation Process
```
Security Tools → API Services → Data Aggregator → Normalized Report Data
```

**Key Services:**
- `ipsstcApi.ts`: Interfaces with GVM, Wazuh, ZAP Proxy
- `agenticPentestApi.ts`: Manages AI-driven penetration testing sessions
- `fastApiClient.ts`: General-purpose API client with resilience features

---

## Complete Report Generation Flow

### Phase 1: Report Initialization

**User Input:**
1. User configures report via `IntelligentReportingSystem.tsx` component
2. Selects report template (Vulnerability Assessment, Penetration Test, Compliance Audit, etc.)
3. Chooses target audience (CISO, Security Engineers, Compliance Officers, Developers)
4. Provides optional custom instructions
5. Selects LLM provider (OpenAI or Perplexity)

**Configuration Data Structure:**
```typescript
{
  reportTitle: string,
  dataSource: string,
  template: ReportTemplate,
  audience: AudienceProfile,
  customInstructions?: string,
  llmConfig: {
    provider: 'openai' | 'perplexity',
    model: string,
    apiKey: string
  }
}
```

---

### Phase 2: Security Data Gathering

**Function:** `gatherReportData(dataSource: string)`

**Process:**
1. System identifies the selected data source
2. Calls appropriate API service methods:
   - **GVM Data**: `ipsstcApi.getVulnerabilities()`
   - **Wazuh Data**: `ipsstcApi.getWazuhAlerts()`
   - **ZAP Data**: `ipsstcApi.getZapScans()`
   - **Pentest Data**: `agenticPentestApi.getSessionStatus()`

3. Aggregates raw data into normalized structure:
```typescript
{
  vulnerabilities: [
    {
      id: string,
      severity: 'critical' | 'high' | 'medium' | 'low',
      title: string,
      description: string,
      affectedAssets: string[],
      cvss_score: number,
      remediation: string
    }
  ],
  scanResults: {
    totalScans: number,
    completedScans: number,
    findings: object[]
  },
  securityEvents: {
    totalEvents: number,
    criticalAlerts: number,
    eventTypes: object[]
  },
  complianceStatus: {
    framework: string,
    complianceLevel: number,
    gaps: string[]
  }
}
```

**Error Handling:**
- Implements retry logic with exponential backoff
- Falls back to cached data if APIs are unavailable
- Logs all data collection errors for debugging

---

### Phase 3: Online Research Integration

**Function:** `conductOnlineResearch(query: string)`

**Purpose:** Enhance report with latest security research, CVE details, and best practices

**Process:**
1. Constructs research query based on:
   - Found vulnerabilities (CVE IDs)
   - Security tool names
   - Attack vectors identified
   - Compliance frameworks referenced

2. Calls Perplexity API for real-time research:
```typescript
POST https://api.perplexity.ai/chat/completions
{
  model: "llama-3.1-sonar-small-128k-online",
  messages: [
    {
      role: "system",
      content: "You are a security research assistant..."
    },
    {
      role: "user",
      content: "Research query with specific CVEs and vulnerabilities"
    }
  ]
}
```

3. Extracts relevant information:
   - Latest exploit details
   - Vendor patch information
   - Real-world attack examples
   - Industry remediation strategies

**Research Output:**
```typescript
{
  researchData: string, // Markdown-formatted research findings
  sources: string[],    // URLs to referenced materials
  timestamp: Date
}
```

---

### Phase 4: AI-Powered Content Adaptation

**Function:** `generateAdaptedContent(reportData, audienceProfile, template)`

**Service:** `openaiService.ts`

**Process:**

#### Step 4.1: System Prompt Construction
Creates audience-specific system prompt:
```typescript
const systemPrompt = `
You are an expert cybersecurity report writer specializing in ${audienceType}.

Report Template: ${templateName}
Target Audience: ${audienceProfile.description}

Audience Priorities:
${audienceProfile.priorities.join('\n')}

Tone: ${audienceProfile.preferredTone}
Technical Depth: ${audienceProfile.technicalDepth}

Guidelines:
- Use ${audienceProfile.preferredTone} language
- Focus on ${audienceProfile.priorities.join(', ')}
- Include ${audienceProfile.preferredFormat} formatting
- Emphasize ${audienceProfile.keyMetrics.join(', ')}
`;
```

#### Step 4.2: Content Generation Request
Calls OpenAI API via `openaiService.generateSecurityReport()`:
```typescript
{
  model: 'gpt-4',
  messages: [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userPrompt }
  ],
  temperature: 0.3,      // Lower for consistency
  max_tokens: 4000       // Sufficient for detailed reports
}
```

#### Step 4.3: Audience-Specific Adaptation

**For CISO Audience:**
- Executive summary with business impact
- Risk prioritization matrix
- Budget implications
- Board-ready metrics
- Strategic recommendations

**For Security Engineers:**
- Detailed technical analysis
- Exploitation techniques
- Step-by-step remediation procedures
- Code examples and configurations
- Tool-specific commands

**For Compliance Officers:**
- Regulatory mapping (GDPR, HIPAA, PCI-DSS, SOC 2)
- Control gap analysis
- Audit evidence requirements
- Policy recommendations
- Compliance timelines

**For Developers:**
- Vulnerable code patterns
- Secure coding examples
- OWASP references
- Library/dependency updates
- CI/CD integration guidance

---

### Phase 5: Research Enhancement

**Function:** `enhanceWithResearch(content, researchData)`

**Purpose:** Integrate online research findings into generated report

**Process:**
1. Takes generated report content
2. Merges with Perplexity research data
3. Calls OpenAI to seamlessly integrate:
```typescript
{
  model: 'gpt-4',
  messages: [
    {
      role: 'system',
      content: 'Integrate research findings into report...'
    },
    {
      role: 'user',
      content: `
        Original Report: ${content}
        Research Data: ${researchData}
        
        Enhance report with research while maintaining structure.
      `
    }
  ],
  temperature: 0.2,  // Very low for accuracy
  max_tokens: 4000
}
```

**Enhancement Includes:**
- Real-world CVE exploitation examples
- Latest vendor patches and timelines
- Industry-specific attack trends
- Updated remediation strategies

---

### Phase 6: Executive Summary Generation

**Function:** `generateExecutiveSummary(detailedReport)`

**Purpose:** Create concise C-level summary

**Process:**
```typescript
openaiService.generateExecutiveSummary(detailedReport)
```

**Output Requirements:**
- 2-3 paragraphs maximum
- Business impact focus
- Critical risks highlighted
- Clear action items
- ROI implications
- Strategic recommendations

---

### Phase 7: Report Formatting & Finalization

**Function:** `formatReport(content)`

**Adds:**
```typescript
{
  metadata: {
    title: string,
    generatedBy: 'AI Security Reporting System',
    generatedAt: ISO8601 timestamp,
    dataSource: string,
    audience: string,
    template: string,
    version: '1.0'
  },
  executiveSummary: string,
  mainContent: string,
  appendices: {
    rawData: object,
    researchSources: string[],
    technicalDetails: object
  }
}
```

**Output Format:**
- Markdown for easy conversion
- Structured sections with proper heading hierarchy
- Embedded tables and charts
- Code blocks with syntax highlighting
- Reference links

---

## Backend Implementation Requirements

### API Endpoints Needed

#### 1. Report Generation Endpoint
```
POST /api/reports/generate
Request Body:
{
  reportConfig: {
    title: string,
    dataSource: string,
    templateId: string,
    audienceId: string,
    customInstructions?: string
  },
  llmConfig: {
    provider: string,
    model: string
  }
}

Response:
{
  jobId: string,
  status: 'queued' | 'processing' | 'completed' | 'failed',
  estimatedCompletionTime: ISO8601
}
```

#### 2. Report Status Endpoint
```
GET /api/reports/status/{jobId}
Response:
{
  jobId: string,
  status: string,
  progress: number,  // 0-100
  currentPhase: string,
  error?: string
}
```

#### 3. Report Retrieval Endpoint
```
GET /api/reports/{jobId}
Response:
{
  reportId: string,
  content: string,  // Markdown formatted
  metadata: object,
  generatedAt: ISO8601,
  downloadUrl: string
}
```

#### 4. Security Data Endpoint
```
GET /api/security/data?source={source}
Response:
{
  source: string,
  data: object,
  collectedAt: ISO8601,
  recordCount: number
}
```

#### 5. Research Query Endpoint
```
POST /api/research/query
Request Body:
{
  query: string,
  context: object
}

Response:
{
  findings: string,
  sources: string[],
  queriedAt: ISO8601
}
```

---

## Database Schema

### Reports Table
```sql
CREATE TABLE reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  metadata JSONB NOT NULL,
  template_id TEXT NOT NULL,
  audience_id TEXT NOT NULL,
  data_source TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  created_by UUID REFERENCES auth.users(id),
  status TEXT NOT NULL DEFAULT 'draft',
  version INTEGER DEFAULT 1
);
```

### Report Jobs Table
```sql
CREATE TABLE report_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  report_id UUID REFERENCES reports(id),
  status TEXT NOT NULL DEFAULT 'queued',
  progress INTEGER DEFAULT 0,
  current_phase TEXT,
  error_message TEXT,
  started_at TIMESTAMP WITH TIME ZONE,
  completed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

---

## Error Handling & Resilience

### Circuit Breaker Pattern
- Prevents cascade failures when external APIs are down
- Trips after 5 consecutive failures
- Half-open state after 30 seconds
- Fully resets after 2 successful calls

### Retry Logic
- Exponential backoff: 1s, 2s, 4s, 8s, 16s
- Maximum 5 retry attempts
- Jitter added to prevent thundering herd

### Fallback Strategies
1. **Data Collection Failure**: Use cached data from previous successful scan
2. **Research API Failure**: Proceed without enhancement
3. **LLM API Failure**: Return raw aggregated data with error notification
4. **Partial Failures**: Generate report with available data, note missing sections

---

## Security Considerations

### API Key Management
- Never store API keys in frontend code
- Use backend environment variables or secrets manager
- Rotate keys regularly
- Implement key-specific rate limiting

### Data Privacy
- Sanitize sensitive data before sending to LLM APIs
- Implement data retention policies
- Encrypt reports at rest
- Audit all report access

### Rate Limiting
- OpenAI: 10,000 requests/day (GPT-4)
- Perplexity: 50 requests/minute
- Implement request queuing for fairness
- Cache research results for 24 hours

---

## Performance Optimization

### Caching Strategy
- Security data: 15 minutes TTL
- Research results: 24 hours TTL
- Generated reports: Indefinite (until invalidated)
- Use Redis for distributed caching

### Async Processing
- Report generation runs as background job
- WebSocket notifications for progress updates
- Job queue with priority levels

### Batch Processing
- Aggregate multiple data source calls
- Parallel API requests where possible
- Stream LLM responses for faster TTFB

---

## Monitoring & Observability

### Key Metrics
- Report generation time (p50, p95, p99)
- API failure rates by service
- LLM token usage and costs
- Cache hit rates
- User satisfaction scores

### Logging
- Structured logs in JSON format
- Log levels: DEBUG, INFO, WARN, ERROR
- Include trace IDs for request correlation
- Sensitive data redaction

### Alerting
- High API failure rates (>5%)
- Slow report generation (>2 minutes)
- LLM API quota exceeded
- Circuit breaker trips

---

## Testing Strategy

### Unit Tests
- Test each data aggregation function
- Mock external API responses
- Validate report structure
- Test error handling paths

### Integration Tests
- End-to-end report generation
- Test all data source combinations
- Verify LLM integration
- Test fallback mechanisms

### Load Tests
- Simulate 100 concurrent report generations
- Test API rate limiting behavior
- Measure system degradation under load
- Validate auto-scaling triggers

---

## Deployment Checklist

- [ ] Configure all API keys in secrets manager
- [ ] Set up database tables and indexes
- [ ] Deploy edge functions for report generation
- [ ] Configure caching layer (Redis)
- [ ] Set up monitoring and alerting
- [ ] Test all data source integrations
- [ ] Verify LLM API connectivity
- [ ] Run load tests
- [ ] Document runbook procedures
- [ ] Train support team on common issues
