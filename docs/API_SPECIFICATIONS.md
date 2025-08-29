# IPS Security Center - API Specifications

## API Overview

The IPS Security Center API is built with FastAPI and provides comprehensive endpoints for managing security tools, conducting penetration tests, and monitoring security alerts in real-time.

**Base URL**: `https://api.ips-security.com`
**API Version**: `v1`
**Authentication**: JWT Bearer Token

## Authentication

### JWT Token Structure
```json
{
  "sub": "user@example.com",
  "role": "admin|analyst|viewer",
  "exp": 1640995200,
  "iat": 1640908800
}
```

### Authentication Endpoints

#### POST /api/v1/auth/login
Authenticate user and receive JWT tokens.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": {
    "id": "uuid-string",
    "email": "user@example.com",
    "full_name": "John Doe",
    "role": "admin",
    "is_active": true
  }
}
```

#### POST /api/v1/auth/refresh
Refresh access token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### POST /api/v1/auth/logout
Invalidate current tokens.

#### GET /api/v1/auth/me
Get current user information.

**Response:**
```json
{
  "id": "uuid-string",
  "email": "user@example.com",
  "full_name": "John Doe",
  "role": "admin",
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z"
}
```

## Security Services

### Health Check Endpoints

#### GET /api/v1/security/health
Check health status of all integrated security services.

**Response:**
```json
{
  "overall_status": "healthy|degraded|unhealthy",
  "services": {
    "wazuh": {
      "status": "healthy",
      "version": "4.5.0",
      "last_check": "2024-01-15T10:30:00Z",
      "response_time": 120
    },
    "gvm": {
      "status": "healthy",
      "version": "22.4",
      "last_check": "2024-01-15T10:30:00Z",
      "response_time": 250
    },
    "zap": {
      "status": "healthy",
      "version": "2.12.0",
      "last_check": "2024-01-15T10:30:00Z",
      "response_time": 180
    },
    "spiderfoot": {
      "status": "healthy",
      "version": "4.0",
      "last_check": "2024-01-15T10:30:00Z",
      "response_time": 200
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Wazuh Integration

### GET /api/v1/security/wazuh/agents
Get list of Wazuh agents with filtering and pagination.

**Query Parameters:**
- `limit` (int): Number of results to return (default: 100, max: 1000)
- `offset` (int): Number of results to skip (default: 0)
- `status` (string): Filter by agent status (active, disconnected, pending)
- `search` (string): Search agents by name or IP
- `os_platform` (string): Filter by OS platform

**Response:**
```json
{
  "data": [
    {
      "id": "001",
      "name": "web-server-01",
      "ip": "192.168.1.100",
      "status": "active",
      "os": {
        "platform": "ubuntu",
        "version": "20.04",
        "architecture": "x86_64"
      },
      "version": "4.5.0",
      "last_keepalive": "2024-01-15T10:29:45Z",
      "node_name": "wazuh-manager",
      "date_add": "2024-01-10T14:30:00Z"
    }
  ],
  "total": 156,
  "limit": 100,
  "offset": 0
}
```

### GET /api/v1/security/wazuh/alerts
Get Wazuh security alerts with advanced filtering.

**Query Parameters:**
- `limit` (int): Number of results to return
- `offset` (int): Number of results to skip
- `severity` (int): Filter by rule level (1-15)
- `agent_id` (string): Filter by specific agent
- `rule_id` (string): Filter by specific rule
- `time_range` (string): Time range (1h, 24h, 7d, 30d)
- `source_ip` (string): Filter by source IP
- `search` (string): Full-text search in alert description

**Response:**
```json
{
  "data": [
    {
      "id": "alert-uuid",
      "timestamp": "2024-01-15T10:25:30Z",
      "rule": {
        "id": "5710",
        "level": 10,
        "description": "Multiple authentication failures",
        "groups": ["authentication_failed", "brute_force"]
      },
      "agent": {
        "id": "001",
        "name": "web-server-01",
        "ip": "192.168.1.100"
      },
      "location": "/var/log/auth.log",
      "decoder": {
        "name": "sshd",
        "parent": "unix_audit"
      },
      "data": {
        "srcip": "203.0.113.42",
        "srcport": "45123",
        "dstuser": "admin",
        "protocol": "ssh"
      },
      "previous_output": "Jan 15 10:25:30 web-server-01 sshd[12345]: Failed password for admin from 203.0.113.42 port 45123 ssh2"
    }
  ],
  "total": 1250,
  "limit": 100,
  "offset": 0,
  "aggregations": {
    "by_severity": {
      "critical": 45,
      "high": 120,
      "medium": 580,
      "low": 505
    },
    "by_agent": {
      "001": 450,
      "002": 320,
      "003": 480
    }
  }
}
```

### PUT /api/v1/security/wazuh/agents/{agent_id}/restart
Restart a specific Wazuh agent.

**Required Role**: `admin` or `analyst`

**Response:**
```json
{
  "status": "success",
  "message": "Agent restart command sent successfully",
  "agent_id": "001",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### GET /api/v1/security/wazuh/rules
Get Wazuh rules with filtering.

**Query Parameters:**
- `limit`, `offset`: Pagination
- `level`: Filter by rule level
- `group`: Filter by rule group
- `search`: Search in rule description

### POST /api/v1/security/wazuh/rules
Create custom Wazuh rule.

**Request Body:**
```json
{
  "rule": {
    "id": "100001",
    "level": 8,
    "description": "Custom security rule",
    "groups": ["custom", "web"],
    "rule_xml": "<rule id=\"100001\" level=\"8\">...</rule>"
  }
}
```

## GVM/OpenVAS Integration

### GET /api/v1/security/gvm/targets
Get vulnerability scan targets.

**Response:**
```json
{
  "data": [
    {
      "id": "target-uuid",
      "name": "Web Application Servers",
      "hosts": ["192.168.1.100-110", "web.example.com"],
      "exclude_hosts": ["192.168.1.105"],
      "port_list": {
        "id": "port-list-uuid",
        "name": "Full and fast"
      },
      "alive_test": "ICMP Ping",
      "created": "2024-01-10T14:30:00Z",
      "modified": "2024-01-15T09:15:00Z"
    }
  ],
  "total": 25
}
```

### POST /api/v1/security/gvm/targets
Create new scan target.

**Request Body:**
```json
{
  "name": "New Target",
  "hosts": ["192.168.1.200-210"],
  "port_list_id": "port-list-uuid",
  "alive_test": "ICMP Ping",
  "credentials": [
    {
      "type": "ssh",
      "username": "scanner",
      "private_key": "ssh-private-key-content"
    }
  ]
}
```

### GET /api/v1/security/gvm/scans
Get vulnerability scans with status and results.

**Query Parameters:**
- `status`: Filter by scan status (running, stopped, done)
- `target_id`: Filter by target
- `config_id`: Filter by scan configuration

**Response:**
```json
{
  "data": [
    {
      "id": "scan-uuid",
      "name": "Weekly Infrastructure Scan",
      "target": {
        "id": "target-uuid",
        "name": "Web Application Servers"
      },
      "config": {
        "id": "config-uuid",
        "name": "Full and fast"
      },
      "status": "done",
      "progress": 100,
      "start_time": "2024-01-15T08:00:00Z",
      "end_time": "2024-01-15T10:30:00Z",
      "results_count": {
        "total": 156,
        "high": 8,
        "medium": 42,
        "low": 89,
        "log": 17
      }
    }
  ]
}
```

### POST /api/v1/security/gvm/scans
Start new vulnerability scan.

**Request Body:**
```json
{
  "name": "Emergency Scan",
  "target_id": "target-uuid",
  "config_id": "config-uuid",
  "scanner_id": "scanner-uuid",
  "schedule": {
    "type": "once|daily|weekly|monthly",
    "start_time": "2024-01-16T02:00:00Z",
    "timezone": "UTC"
  }
}
```

### GET /api/v1/security/gvm/scans/{scan_id}/report
Get detailed scan report.

**Query Parameters:**
- `format`: Report format (json, xml, pdf, html)
- `severity`: Filter results by severity
- `host`: Filter results by host

**Response:**
```json
{
  "scan": {
    "id": "scan-uuid",
    "name": "Weekly Infrastructure Scan",
    "start_time": "2024-01-15T08:00:00Z",
    "end_time": "2024-01-15T10:30:00Z"
  },
  "summary": {
    "total_vulnerabilities": 156,
    "high": 8,
    "medium": 42,
    "low": 89,
    "hosts_scanned": 11,
    "hosts_with_vulnerabilities": 8
  },
  "vulnerabilities": [
    {
      "id": "vuln-uuid",
      "name": "Apache HTTP Server Information Disclosure",
      "severity": "medium",
      "cvss_score": 5.0,
      "cve": ["CVE-2023-1234"],
      "host": "192.168.1.100",
      "port": "80/tcp",
      "description": "Detailed vulnerability description...",
      "solution": "Update Apache to version 2.4.58 or later",
      "references": [
        "https://httpd.apache.org/security/vulnerabilities_24.html"
      ]
    }
  ]
}
```

## OWASP ZAP Integration

### POST /api/v1/security/zap/scans
Start web application security scan.

**Request Body:**
```json
{
  "name": "E-commerce Application Scan",
  "target": "https://shop.example.com",
  "scan_type": "baseline|full|api",
  "config": {
    "spider": {
      "enabled": true,
      "max_depth": 5,
      "max_duration": 30
    },
    "active_scan": {
      "enabled": true,
      "policy": "default",
      "max_duration": 120
    },
    "authentication": {
      "type": "form|basic|bearer",
      "login_url": "https://shop.example.com/login",
      "username": "testuser",
      "password": "testpass",
      "username_field": "email",
      "password_field": "password"
    },
    "context": {
      "include_urls": ["https://shop.example.com/*"],
      "exclude_urls": ["https://shop.example.com/logout"]
    }
  }
}
```

**Response:**
```json
{
  "scan_id": "scan-uuid",
  "status": "started",
  "message": "Web application scan initiated successfully",
  "estimated_duration": "45-90 minutes",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### GET /api/v1/security/zap/scans/{scan_id}
Get scan status and progress.

**Response:**
```json
{
  "id": "scan-uuid",
  "name": "E-commerce Application Scan",
  "target": "https://shop.example.com",
  "status": "running|completed|failed",
  "progress": {
    "spider": {
      "status": "completed",
      "progress": 100,
      "urls_found": 1250
    },
    "active_scan": {
      "status": "running",
      "progress": 65,
      "current_plugin": "SQL Injection"
    }
  },
  "start_time": "2024-01-15T10:30:00Z",
  "estimated_completion": "2024-01-15T12:00:00Z",
  "alerts_count": {
    "high": 3,
    "medium": 12,
    "low": 28,
    "informational": 45
  }
}
```

### GET /api/v1/security/zap/scans/{scan_id}/report
Get detailed scan report.

**Response:**
```json
{
  "scan": {
    "id": "scan-uuid",
    "name": "E-commerce Application Scan",
    "target": "https://shop.example.com",
    "scan_type": "full",
    "start_time": "2024-01-15T10:30:00Z",
    "end_time": "2024-01-15T11:45:00Z",
    "duration": "1h 15m"
  },
  "summary": {
    "total_alerts": 88,
    "urls_tested": 1250,
    "risk_levels": {
      "high": 3,
      "medium": 12,
      "low": 28,
      "informational": 45
    }
  },
  "alerts": [
    {
      "id": "alert-uuid",
      "alert": "SQL Injection",
      "risk": "high",
      "confidence": "medium",
      "url": "https://shop.example.com/search?q=test",
      "param": "q",
      "method": "GET",
      "evidence": "ORA-01756: quoted string not properly terminated",
      "description": "SQL injection may be possible...",
      "solution": "Use prepared statements or parameterized queries...",
      "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
      "cwe_id": 89,
      "wasc_id": 19
    }
  ]
}
```

## SpiderFoot Integration

### POST /api/v1/security/spiderfoot/scans
Start OSINT reconnaissance scan.

**Request Body:**
```json
{
  "name": "Company Domain Reconnaissance",
  "target": "example.com",
  "scan_type": "domain|ip|email|company",
  "modules": [
    "dns",
    "subdomain_enum",
    "email_harvest",
    "social_media",
    "certificate_transparency",
    "whois"
  ],
  "config": {
    "max_threads": 10,
    "delay": 1,
    "timeout": 30
  }
}
```

### GET /api/v1/security/spiderfoot/scans/{scan_id}/results
Get reconnaissance scan results.

**Response:**
```json
{
  "scan": {
    "id": "scan-uuid",
    "name": "Company Domain Reconnaissance",
    "target": "example.com",
    "status": "completed",
    "modules_run": 15,
    "start_time": "2024-01-15T10:00:00Z",
    "end_time": "2024-01-15T10:45:00Z"
  },
  "results": {
    "subdomains": [
      "www.example.com",
      "mail.example.com",
      "api.example.com",
      "admin.example.com"
    ],
    "ip_addresses": [
      "203.0.113.10",
      "203.0.113.11"
    ],
    "email_addresses": [
      "contact@example.com",
      "support@example.com"
    ],
    "certificates": [
      {
        "subject": "CN=*.example.com",
        "issuer": "Let's Encrypt",
        "valid_from": "2024-01-01T00:00:00Z",
        "valid_to": "2024-04-01T00:00:00Z"
      }
    ],
    "social_media": [
      {
        "platform": "twitter",
        "url": "https://twitter.com/example_company",
        "followers": 5420
      }
    ]
  }
}
```

## WebSocket API

### WS /api/v1/ws/security-alerts
Real-time security alerts WebSocket connection.

**Authentication**: JWT token as query parameter or in first message

**Connection:**
```
wss://api.ips-security.com/api/v1/ws/security-alerts?token=JWT_TOKEN
```

**Message Types:**

#### Client to Server:
```json
{
  "type": "subscribe",
  "channels": ["wazuh_alerts", "gvm_scans", "zap_alerts"],
  "filters": {
    "severity": ["high", "critical"],
    "agent_ids": ["001", "002"]
  }
}
```

#### Server to Client:
```json
{
  "type": "security_alert",
  "source": "wazuh",
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "high",
  "alert": {
    "id": "alert-uuid",
    "rule_id": "5710",
    "description": "Multiple authentication failures",
    "agent": {
      "id": "001",
      "name": "web-server-01"
    },
    "data": {
      "srcip": "203.0.113.42",
      "attempts": 5
    }
  }
}
```

## Error Handling

### Standard Error Response
```json
{
  "detail": "Error message",
  "error_code": "ERROR_CODE",
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req-uuid"
}
```

### HTTP Status Codes
- `200`: Success
- `201`: Created
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `422`: Validation Error
- `429`: Rate Limited
- `500`: Internal Server Error
- `503`: Service Unavailable

### Common Error Codes
- `INVALID_CREDENTIALS`: Invalid username/password
- `TOKEN_EXPIRED`: JWT token has expired
- `INSUFFICIENT_PERMISSIONS`: User lacks required permissions
- `SERVICE_UNAVAILABLE`: Security service is not available
- `SCAN_IN_PROGRESS`: Cannot start scan while another is running
- `INVALID_TARGET`: Invalid scan target specification
- `QUOTA_EXCEEDED`: User has exceeded their quota limits

## Rate Limiting

**Default Limits:**
- Authentication endpoints: 5 requests per minute
- Standard endpoints: 100 requests per minute
- WebSocket connections: 10 concurrent per user
- Scan operations: 5 concurrent scans per user

**Headers:**
- `X-RateLimit-Limit`: Request limit per window
- `X-RateLimit-Remaining`: Remaining requests in window
- `X-RateLimit-Reset`: Window reset time (Unix timestamp)

## Pagination

**Query Parameters:**
- `limit`: Number of items per page (default: 100, max: 1000)
- `offset`: Number of items to skip (default: 0)

**Response Metadata:**
```json
{
  "data": [...],
  "total": 1500,
  "limit": 100,
  "offset": 200,
  "has_next": true,
  "has_previous": true
}
```

This API specification provides a comprehensive interface for managing security operations, monitoring threats, and conducting security assessments through a unified platform.