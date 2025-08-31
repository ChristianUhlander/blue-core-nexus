# Ticketing System & Attack Plans Guide

## Overview

The Production Security Center implements a continuous **Find-Fix-Verify** security operations model through automated attack plans and integrated ticketing systems. This creates a seamless workflow where security vulnerabilities are automatically discovered, tracked, remediated, and verified.

## Attack Plans Architecture

### What Are Attack Plans?

Attack Plans are **automated, scheduled security assessments** that continuously monitor your infrastructure for vulnerabilities. Think of them as your security team's automated assistants that never sleep.

### Core Components

#### 1. **Automated Scanning Engine**
```typescript
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
```

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
```json
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
```

#### ServiceNow Integration  
```json
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
```

#### Custom API Integration
```json
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
```

## Ticket Structure & Format

### Standard Ticket Fields

Every automatically generated ticket contains:

```typescript
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
```

### Example Generated Ticket

```markdown
**Title**: Critical SQL Injection Vulnerability in User Authentication

**Description**: 
A SQL injection vulnerability was discovered in the user login endpoint that allows attackers to bypass authentication and potentially access sensitive user data.

**Technical Details**:
- **Endpoint**: https://app.company.com/api/login
- **Parameter**: username (POST body)
- **Attack Vector**: `admin' OR '1'='1' --`
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
```

## Remediation Tracking Workflow

### Lifecycle States

```typescript
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
```

### State Transitions

1. **Open**: Vulnerability discovered, ticket created
2. **In Progress**: Developer/team assigned and working on fix
3. **Resolved**: Fix implemented, ready for verification
4. **Verified**: Automated retest confirms vulnerability is fixed
5. **Reopened**: Retest failed, vulnerability still present

### Automated Verification Process

```python
# Pseudo-code for automated verification
async def verify_vulnerability_fix(tracking_item):
    """
    Automatically retest resolved vulnerabilities
    """
    vulnerability = get_vulnerability(tracking_item.vulnerability_id)
    
    # Wait for deployment window
    if tracking_item.retest_schedule > now():
        schedule_retest(tracking_item)
        return
    
    # Execute targeted retest
    retest_result = await run_targeted_scan(
        target=vulnerability.affected_assets,
        test_cases=vulnerability.test_cases
    )
    
    if retest_result.vulnerability_found:
        # Still vulnerable - reopen ticket
        update_ticket_status(tracking_item.ticket_id, 'reopened')
        tracking_item.verification_attempts += 1
        
        if tracking_item.verification_attempts >= MAX_ATTEMPTS:
            escalate_to_security_team(tracking_item)
    else:
        # Fixed - mark as verified
        update_ticket_status(tracking_item.ticket_id, 'verified')
        close_vulnerability(tracking_item.vulnerability_id)
```

### SLA and Escalation Rules

#### Priority-Based SLAs
- **Critical**: 24 hours to acknowledge, 72 hours to resolve
- **High**: 48 hours to acknowledge, 7 days to resolve  
- **Medium**: 5 days to acknowledge, 30 days to resolve
- **Low**: 10 days to acknowledge, 90 days to resolve

#### Escalation Triggers
- SLA breach warnings at 75% of time limit
- Automatic escalation to management at SLA breach
- Security team notification for repeated verification failures

## Configuration Best Practices

### Attack Plan Strategy

#### High-Value Targets (Daily Scans)
```javascript
const criticalAssets = [
  'app.company.com',      // Customer-facing application
  'api.company.com',      // Public API endpoints  
  'admin.company.com',    // Administrative interfaces
  'payment.company.com'   // Payment processing
];
```

#### Infrastructure Assessment (Weekly)
```javascript
const infrastructureTargets = [
  '10.0.0.0/24',         // Internal network ranges
  'vpn.company.com',     // VPN endpoints
  'mail.company.com',    // Email infrastructure
  'dns1.company.com'     // DNS servers
];
```

### Ticketing Configuration

#### Auto-Assignment Rules
```json
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
```

#### Notification Settings
```json
{
  "notifications": {
    "new_ticket": ["security-team@company.com"],
    "sla_warning": ["team-lead@company.com", "security-manager@company.com"],
    "verification_failed": ["security-team@company.com", "ciso@company.com"],
    "critical_finding": ["on-call-security@company.com"]
  }
}
```

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

### Sample Dashboard Queries

```sql
-- Average resolution time by severity
SELECT 
  severity,
  AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/3600) as avg_hours_to_resolve
FROM security_tickets 
WHERE status = 'verified'
GROUP BY severity;

-- SLA compliance rate
SELECT 
  priority,
  COUNT(*) as total_tickets,
  SUM(CASE WHEN resolved_within_sla THEN 1 ELSE 0 END) as sla_compliant,
  ROUND(100.0 * SUM(CASE WHEN resolved_within_sla THEN 1 ELSE 0 END) / COUNT(*), 2) as compliance_rate
FROM security_tickets
GROUP BY priority;

-- Top vulnerability categories  
SELECT 
  category,
  COUNT(*) as frequency,
  AVG(cvss_score) as avg_severity
FROM vulnerabilities
WHERE discovered_at >= NOW() - INTERVAL '30 days'
GROUP BY category
ORDER BY frequency DESC;
```

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

### Compliance Mapping
- **SOC 2**: Continuous monitoring and incident response
- **ISO 27001**: Risk management and security controls
- **PCI DSS**: Vulnerability management requirements
- **NIST**: Incident response and recovery procedures

## Troubleshooting Guide

### Common Issues

#### Ticket Creation Failures
```bash
# Check API connectivity
curl -X POST https://company.atlassian.net/rest/api/3/issue \
  -H "Authorization: Basic base64(email:token)" \
  -H "Content-Type: application/json"

# Verify project permissions
GET /rest/api/3/project/{projectKey}/roles
```

#### Verification Loop Issues
- **Problem**: Vulnerability marked as fixed but retest keeps failing
- **Solution**: Check if fix was deployed to scanned environment
- **Debug**: Compare scan timestamps with deployment logs

#### Assignment Rule Conflicts
- **Problem**: Tickets assigned to wrong team/person
- **Solution**: Review assignment rule precedence and conditions
- **Prevention**: Use rule testing with sample vulnerability data

### Monitoring and Alerting

#### System Health Checks
```python
# Monitor attack plan execution
def check_attack_plan_health():
    overdue_plans = get_overdue_attack_plans()
    failed_scans = get_failed_scans(last_24_hours=True)
    
    if overdue_plans:
        alert("Attack plans overdue", details=overdue_plans)
    
    if failed_scans:
        alert("Scan failures detected", details=failed_scans)

# Monitor ticket system integration  
def check_ticketing_health():
    api_status = test_ticketing_api_connectivity()
    pending_tickets = get_tickets_pending_creation()
    
    if not api_status:
        alert("Ticketing API unavailable")
    
    if len(pending_tickets) > THRESHOLD:
        alert("Ticket creation backlog", count=len(pending_tickets))
```

This system creates a robust, automated security operations pipeline that scales with your organization while maintaining the human oversight needed for effective security management.