# Wazuh SIEM Management Guide

## Overview

Wazuh SIEM (Security Information and Event Management) is the centralized security monitoring and incident detection engine of the IPS Security Center. It provides real-time log analysis, threat detection, compliance monitoring, and security incident response capabilities across your entire infrastructure.

## What is Wazuh SIEM?

Wazuh is an open-source security platform that unifies XDR (Extended Detection and Response) and SIEM capabilities. In the context of the IPS Security Center, it serves as:

- **Central Log Aggregator**: Collects security events from all systems
- **Threat Detection Engine**: Analyzes patterns to identify security incidents  
- **Compliance Monitor**: Ensures adherence to security standards
- **Incident Response Hub**: Orchestrates response to security events
- **Forensic Analysis Tool**: Provides detailed investigation capabilities

## Architecture Overview

### Core Components

```typescript
interface WazuhArchitecture {
  manager: {
    role: 'Central coordination and analysis';
    components: ['Rule Engine', 'Event Correlation', 'Alert Management'];
    port: 1514; // Agent communication
    api_port: 55000; // REST API
  };
  agents: {
    role: 'Data collection from endpoints';
    types: ['File Integrity', 'Log Collection', 'Rootkit Detection'];
    communication: 'Encrypted (AES + Blowfish)';
  };
  indexer: {
    role: 'Data storage and search';
    technology: 'OpenSearch/Elasticsearch';
    port: 9200;
  };
  dashboard: {
    role: 'Visualization and management';
    technology: 'OpenSearch Dashboards';
    port: 443;
  };
}
```

### Data Flow Pipeline

```
Log Sources → Wazuh Agents → Wazuh Manager → Rules Engine → Alerts → Dashboard/API
     ↓              ↓              ↓             ↓          ↓         ↓
  Endpoints    Collection     Normalization  Analysis  Notification  Action
```

## Data Sources and Endpoints

### 1. **System Infrastructure Logs**

#### Linux/Unix Systems
```bash
# System logs
/var/log/syslog          # System events
/var/log/auth.log        # Authentication events  
/var/log/secure          # SSH, sudo, su events
/var/log/messages        # General system messages
/var/log/dmesg           # Kernel messages

# Service-specific logs
/var/log/apache2/        # Web server logs
/var/log/nginx/          # Reverse proxy logs
/var/log/mysql/          # Database logs
/var/log/postgresql/     # PostgreSQL logs
```

#### Windows Systems
```powershell
# Event logs
Security                 # Authentication, privileges
System                   # System components, drivers
Application              # Applications, services
Setup                    # System setup, updates

# IIS logs (if applicable)
C:\inetpub\logs\LogFiles\

# Custom application logs
%ProgramData%\ApplicationName\Logs\
```

#### Network Infrastructure
```yaml
# Firewall logs
iptables_logs: /var/log/iptables.log
pf_logs: /var/log/pflog
cisco_asa: syslog_endpoint:514

# Network device logs  
switches: 
  - device: "10.0.1.1"
    type: "cisco_ios"
    syslog_facility: "local0"
    
routers:
  - device: "10.0.1.254" 
    type: "juniper"
    syslog_facility: "local1"
```

### 2. **Application Security Logs**

#### Web Application Logs
```json
{
  "apache_access": {
    "path": "/var/log/apache2/access.log",
    "format": "combined",
    "events": ["HTTP requests", "Response codes", "User agents"]
  },
  "apache_error": {
    "path": "/var/log/apache2/error.log", 
    "events": ["Application errors", "Security warnings", "Module failures"]
  },
  "nginx_access": {
    "path": "/var/log/nginx/access.log",
    "format": "json",
    "events": ["Request details", "Response times", "Client IPs"]
  }
}
```

#### Database Security Events
```sql
-- MySQL/MariaDB
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/general.log';
SET GLOBAL slow_query_log = 'ON';

-- PostgreSQL
log_statement = 'all'
log_connections = on
log_disconnections = on
log_checkpoints = on
```

#### Application Framework Logs
```yaml
# Laravel (PHP)
laravel_logs:
  path: "/var/www/storage/logs/laravel.log"
  events: ["Authentication", "Authorization", "Database queries", "Exceptions"]

# Django (Python)  
django_logs:
  path: "/var/log/django/security.log"
  events: ["Login attempts", "CSRF violations", "SQL injection attempts"]

# Node.js Applications
nodejs_logs:
  path: "/var/log/app/security.log"
  events: ["API calls", "Auth failures", "Rate limit violations"]
```

### 3. **Cloud Infrastructure Logs**

#### AWS CloudTrail Integration
```json
{
  "aws_cloudtrail": {
    "s3_bucket": "company-cloudtrail-logs",
    "regions": ["us-east-1", "us-west-2"],
    "events": [
      "API calls",
      "Console sign-ins", 
      "Resource modifications",
      "IAM changes"
    ],
    "integration_method": "S3 bucket monitoring"
  }
}
```

#### Azure Activity Logs
```json
{
  "azure_activity": {
    "subscription_id": "12345678-1234-1234-1234-123456789012",
    "resource_groups": ["production", "staging"],
    "events": [
      "Resource deployments",
      "RBAC changes",
      "Network security group modifications",
      "Key vault access"
    ]
  }
}
```

#### Google Cloud Audit Logs
```yaml
gcp_audit:
  project_id: "company-production"
  log_types:
    - admin_activity    # Administrative actions
    - data_access      # Data read/write operations
    - system_event     # System-generated events
  export_destination: "pubsub://wazuh-logs-topic"
```

### 4. **Container and Orchestration Logs**

#### Kubernetes Cluster Logs
```yaml
kubernetes_logs:
  api_server: 
    path: "/var/log/kube-apiserver.log"
    events: ["API requests", "Authentication", "Authorization"]
    
  kubelet:
    path: "/var/log/kubelet.log"  
    events: ["Pod lifecycle", "Resource allocation", "Node status"]
    
  audit_logs:
    path: "/var/log/kubernetes/audit.log"
    events: ["Resource access", "Policy violations", "Admin actions"]
```

#### Docker Container Logs
```bash
# Container runtime logs
/var/lib/docker/containers/*/container.log

# Application logs inside containers
Docker logs: docker logs <container_id> 
Syslog integration: --log-driver=syslog --log-opt syslog-address=tcp://wazuh-manager:514
```

### 5. **Security Tool Integration Logs**

#### Vulnerability Scanners
```json
{
  "openvas_logs": {
    "path": "/var/log/gvm/gvmd.log",
    "events": ["Scan initiation", "Vulnerability findings", "Report generation"]
  },
  "nessus_logs": {
    "api_endpoint": "https://nessus.company.com:8834/rest",
    "events": ["Scan results", "Plugin updates", "User activities"]
  }
}
```

#### Penetration Testing Tools
```yaml
zap_integration:
  log_path: "/var/log/zap/zap.log"
  webhook_endpoint: "https://wazuh-manager/webhooks/zap"
  events: ["Scan findings", "Spider results", "Active scan alerts"]

metasploit_logs:
  log_path: "/root/.msf4/logs/"
  events: ["Exploitation attempts", "Payload executions", "Session activities"]
```

## Log Processing and Analysis

### 1. **Log Collection Configuration**

#### Agent Configuration (ossec.conf)
```xml
<ossec_config>
  <!-- Log analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
  
  <!-- File integrity monitoring -->
  <syscheck>
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/var/www</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/mnttab</ignore>
  </syscheck>
  
  <!-- Rootkit detection -->
  <rootcheck>
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
  </rootcheck>
</ossec_config>
```

### 2. **Custom Rule Development**

#### Security Event Rules
```xml
<!-- SQL Injection Detection -->
<rule id="100001" level="12">
  <if_sid>31100</if_sid>
  <regex>union|select|insert|delete|update|drop|create|alter</regex>
  <description>Possible SQL injection attack</description>
  <group>web_attack,sql_injection</group>
</rule>

<!-- Brute Force Detection -->  
<rule id="100002" level="10" frequency="10" timeframe="60">
  <if_matched_sid>5716</if_matched_sid>
  <description>Multiple SSH authentication failures</description>
  <group>authentication_failures,brute_force</group>
</rule>

<!-- Privilege Escalation -->
<rule id="100003" level="8">
  <if_sid>5401</if_sid>
  <regex>sudo: pam_unix\(sudo:auth\): authentication failure</regex>
  <description>Sudo authentication failure</description>
  <group>privilege_escalation</group>
</rule>
```

#### Application-Specific Rules
```xml
<!-- Laravel Application Security -->
<rule id="100010" level="8">
  <regex>production.ERROR: Illuminate\\Auth\\AuthenticationException</regex>
  <description>Laravel authentication failure</description>
  <group>laravel,authentication</group>
</rule>

<!-- API Rate Limiting -->
<rule id="100011" level="6">
  <regex>Rate limit exceeded for IP</regex>
  <description>API rate limit exceeded</description>
  <group>api_security,rate_limiting</group>
</rule>
```

### 3. **Alert Correlation and Analysis**

#### Multi-Stage Attack Detection
```xml
<!-- Stage 1: Reconnaissance -->
<rule id="100020" level="5">
  <if_sid>31100</if_sid>
  <regex>nikto|nmap|sqlmap|dirb|gobuster</regex>
  <description>Security scanning tool detected</description>
  <group>recon,scanning</group>
</rule>

<!-- Stage 2: Exploitation -->
<rule id="100021" level="10">
  <if_sid>100020</if_sid>
  <regex>exploit|payload|shell|backdoor</regex>
  <description>Exploitation attempt after reconnaissance</description>
  <group>exploitation,correlation</group>
</rule>
```

## Integration Patterns

### 1. **REST API Integration**

#### Wazuh Manager API
```python
import requests
from typing import Dict, List

class WazuhAPIClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.authenticate(username, password)
    
    def authenticate(self, username: str, password: str):
        """Authenticate with Wazuh API"""
        auth_data = {
            "username": username,
            "password": password
        }
        response = self.session.post(f"{self.base_url}/security/user/authenticate", json=auth_data)
        token = response.json()["data"]["token"]
        self.session.headers.update({"Authorization": f"Bearer {token}"})
    
    def get_agents(self) -> List[Dict]:
        """Get all registered agents"""
        response = self.session.get(f"{self.base_url}/agents")
        return response.json()["data"]["affected_items"]
    
    def get_alerts(self, limit: int = 500, severity: str = None) -> List[Dict]:
        """Get security alerts"""
        params = {"limit": limit}
        if severity:
            params["q"] = f"rule.level>={severity}"
        
        response = self.session.get(f"{self.base_url}/alerts", params=params)
        return response.json()["data"]["affected_items"]
    
    def get_vulnerabilities(self, agent_id: str = None) -> List[Dict]:
        """Get vulnerability data"""
        endpoint = f"{self.base_url}/vulnerability"
        if agent_id:
            endpoint += f"/{agent_id}"
        
        response = self.session.get(endpoint)
        return response.json()["data"]["affected_items"]
```

#### Real-time Event Streaming
```python
import websocket
import json

class WazuhEventStream:
    def __init__(self, websocket_url: str, auth_token: str):
        self.websocket_url = websocket_url  
        self.auth_token = auth_token
        
    def on_message(self, ws, message):
        """Handle incoming security events"""
        event = json.loads(message)
        
        # Process different event types
        if event.get("rule", {}).get("level", 0) >= 10:
            self.handle_high_severity_alert(event)
        elif "authentication_failure" in event.get("rule", {}).get("groups", []):
            self.handle_auth_failure(event)
        elif "vulnerability" in event.get("data", {}):
            self.handle_vulnerability_event(event)
    
    def handle_high_severity_alert(self, event):
        """Process high-severity security alerts"""
        alert_data = {
            "timestamp": event.get("timestamp"),
            "agent": event.get("agent", {}).get("name"),
            "rule_id": event.get("rule", {}).get("id"),
            "description": event.get("rule", {}).get("description"),
            "level": event.get("rule", {}).get("level"),
            "source_ip": event.get("data", {}).get("srcip"),
            "full_log": event.get("full_log")
        }
        
        # Send to incident response system
        self.create_security_incident(alert_data)
```

### 2. **Syslog Integration**

#### Centralized Syslog Configuration
```bash
# rsyslog configuration for Wazuh integration
# /etc/rsyslog.d/99-wazuh.conf

# Send all security events to Wazuh
auth,authpriv.*                 @@wazuh-manager:514
kern.warning                    @@wazuh-manager:514
mail.*                          @@wazuh-manager:514
daemon.info                     @@wazuh-manager:514

# Custom application logs
local0.*                        @@wazuh-manager:514  # Web applications
local1.*                        @@wazuh-manager:514  # API services  
local2.*                        @@wazuh-manager:514  # Database logs
```

#### Application Syslog Integration
```python
import syslog
import json

class SecurityLogger:
    def __init__(self, facility=syslog.LOG_LOCAL0):
        syslog.openlog("security-app", syslog.LOG_PID, facility)
    
    def log_authentication_attempt(self, username: str, ip: str, success: bool):
        """Log authentication events"""
        event = {
            "event_type": "authentication",
            "username": username,
            "source_ip": ip,
            "success": success,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        priority = syslog.LOG_INFO if success else syslog.LOG_WARNING
        syslog.syslog(priority, f"AUTH_EVENT: {json.dumps(event)}")
    
    def log_api_access(self, endpoint: str, method: str, status_code: int, ip: str):
        """Log API access events"""
        event = {
            "event_type": "api_access",
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "source_ip": ip,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        priority = syslog.LOG_WARNING if status_code >= 400 else syslog.LOG_INFO
        syslog.syslog(priority, f"API_EVENT: {json.dumps(event)}")
```

## Alert Management and Response

### 1. **Alert Severity Classification**

```yaml
severity_levels:
  0-3:   # Informational
    priority: "Low"
    response_time: "24 hours"
    action: "Log for analysis"
    
  4-7:   # Warning  
    priority: "Medium"
    response_time: "4 hours"
    action: "Investigate and assess"
    
  8-11:  # Error
    priority: "High" 
    response_time: "1 hour"
    action: "Immediate investigation"
    
  12-15: # Critical
    priority: "Critical"
    response_time: "15 minutes"
    action: "Immediate response and containment"
```

### 2. **Automated Response Actions**

#### Active Response Configuration
```xml
<ossec_config>
  <active-response>
    <command>firewall-block</command>
    <location>local</location>
    <level>10</level>
    <timeout>600</timeout>
  </active-response>
  
  <active-response>
    <command>disable-account</command>
    <location>local</location>
    <rules_id>100002</rules_id> <!-- Brute force attempts -->
  </active-response>
</ossec_config>
```

#### Custom Response Scripts
```bash
#!/bin/bash
# /var/ossec/active-response/bin/security-response.sh

ACTION=$1
USER=$2
IP=$3
ALERT_ID=$4

case $ACTION in
  add)
    # Block IP address
    iptables -I INPUT -s $IP -j DROP
    
    # Log the action
    logger "Wazuh: Blocked IP $IP due to security alert $ALERT_ID"
    
    # Send notification to security team
    curl -X POST https://slack.webhook.url \
      -d "{\"text\":\"Security Alert: Blocked IP $IP - Alert ID: $ALERT_ID\"}"
    ;;
    
  delete)
    # Unblock IP address after timeout
    iptables -D INPUT -s $IP -j DROP
    logger "Wazuh: Unblocked IP $IP"
    ;;
esac
```

## Compliance and Reporting

### 1. **Compliance Framework Mapping**

#### PCI DSS Requirements
```yaml
pci_dss_mapping:
  requirement_10:  # Logging and monitoring
    rules: [5700, 5701, 5706, 5707]  # Authentication events
    description: "Track and monitor all access to network resources"
    
  requirement_11:  # Security testing
    rules: [100001, 100020, 100021]  # Attack detection
    description: "Regularly test security systems and processes"
```

#### SOC 2 Type II Controls
```yaml
soc2_controls:
  cc6_1:  # Logical access controls
    events: ["login_success", "login_failure", "privilege_escalation"]
    retention: "365 days"
    
  cc6_7:  # Data transmission controls  
    events: ["ssl_errors", "encryption_failures", "data_exfiltration"]
    alert_threshold: "Any occurrence"
```

### 2. **Automated Reporting**

#### Daily Security Summary
```python
def generate_daily_security_report():
    """Generate daily security summary report"""
    
    # Get alerts from last 24 hours
    alerts = wazuh_client.get_alerts(
        time_range="24h",
        severity_min=5
    )
    
    # Categorize alerts
    categories = {
        "authentication": [],
        "network": [],
        "malware": [],
        "vulnerability": [],
        "compliance": []
    }
    
    for alert in alerts:
        for group in alert.get("rule", {}).get("groups", []):
            if group in categories:
                categories[group].append(alert)
    
    # Generate report
    report = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "total_alerts": len(alerts),
        "by_category": {k: len(v) for k, v in categories.items()},
        "top_sources": get_top_alert_sources(alerts),
        "critical_incidents": [a for a in alerts if a["rule"]["level"] >= 12]
    }
    
    return report
```

## Performance Optimization

### 1. **Log Processing Optimization**

#### Rule Performance Tuning
```xml
<!-- Efficient rule structure -->
<rule id="100030" level="0">
  <if_sid>5716</if_sid>
  <regex>^Failed password for</regex>
  <description>SSH authentication failure (parent rule)</description>
</rule>

<rule id="100031" level="5">
  <if_sid>100030</if_sid>
  <regex>invalid user</regex>
  <description>SSH login attempt with invalid user</description>
  <group>authentication_failures</group>
</rule>
```

#### Log Parsing Optimization
```yaml
# Optimized log formats
json_logs:
  enabled: true
  benefits: ["Faster parsing", "Structured data", "Better indexing"]
  
multiline_logs:
  handling: "Use log_format=multi-line"
  performance: "Pre-process when possible"
  
large_files:
  rotation: "Implement log rotation"
  monitoring: "Monitor disk usage"
```

### 2. **Storage and Indexing**

#### Index Management
```json
{
  "index_template": {
    "wazuh-alerts": {
      "mappings": {
        "properties": {
          "timestamp": {"type": "date"},
          "agent.name": {"type": "keyword"},
          "rule.level": {"type": "integer"},
          "rule.id": {"type": "keyword"},
          "data.srcip": {"type": "ip"},
          "full_log": {"type": "text", "index": false}
        }
      },
      "settings": {
        "number_of_shards": 3,
        "number_of_replicas": 1,
        "refresh_interval": "30s"
      }
    }
  }
}
```

## Monitoring and Maintenance

### 1. **System Health Monitoring**

```python
def check_wazuh_health():
    """Monitor Wazuh system health"""
    
    health_status = {
        "manager": check_manager_status(),
        "agents": check_agent_connectivity(),
        "indexer": check_indexer_health(),
        "disk_usage": check_disk_usage(),
        "rule_performance": check_rule_performance()
    }
    
    # Alert on issues
    for component, status in health_status.items():
        if not status["healthy"]:
            send_alert(f"Wazuh {component} issue: {status['message']}")
    
    return health_status

def check_agent_connectivity():
    """Check agent connectivity status"""
    agents = wazuh_client.get_agents()
    
    disconnected = [a for a in agents if a["status"] != "active"]
    never_connected = [a for a in agents if a.get("last_keep_alive") is None]
    
    return {
        "healthy": len(disconnected) == 0,
        "total_agents": len(agents),
        "disconnected": len(disconnected),
        "never_connected": len(never_connected),
        "details": disconnected + never_connected
    }
```

### 2. **Maintenance Tasks**

#### Regular Maintenance Schedule
```bash
#!/bin/bash
# Daily maintenance script

# Clean old logs (keep 90 days)
find /var/ossec/logs -name "*.log" -mtime +90 -delete

# Optimize indices  
curl -X POST "localhost:9200/wazuh-alerts-*/_forcemerge?max_num_segments=1"

# Update rules and decoders
/var/ossec/bin/update_ruleset

# Restart if needed
if [ -f /var/ossec/var/run/.restart ]; then
    systemctl restart wazuh-manager
    rm /var/ossec/var/run/.restart
fi

# Generate health report
python3 /opt/scripts/wazuh_health_check.py
```

This comprehensive guide provides the foundation for implementing a robust, scalable Wazuh SIEM deployment that effectively monitors your entire security infrastructure and provides actionable intelligence for threat detection and response.