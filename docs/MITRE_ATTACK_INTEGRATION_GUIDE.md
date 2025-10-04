# MITRE ATT&CK Framework Integration Guide

## Overview

This guide provides backend developers with comprehensive instructions for implementing MITRE ATT&CK framework mapping in the IPS Security Center GUI. The implementation is based on Wazuh's official MITRE ATT&CK integration methodology and extends it with intelligent visualization and analysis capabilities.

## Table of Contents

1. [Understanding MITRE ATT&CK Framework](#understanding-mitre-attck-framework)
2. [Wazuh Alert Structure](#wazuh-alert-structure)
3. [Data Flow Architecture](#data-flow-architecture)
4. [Backend API Requirements](#backend-api-requirements)
5. [Database Schema](#database-schema)
6. [MITRE Mapping Logic](#mitre-mapping-logic)
7. [Visualization Best Practices](#visualization-best-practices)
8. [Integration with Reporting System](#integration-with-reporting-system)

---

## Understanding MITRE ATT&CK Framework

### Framework Components

**MITRE ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) consists of:

- **Tactics (14 total)**: The "why" of an attack - the adversary's tactical goal
  - Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact, Reconnaissance, Resource Development

- **Techniques**: The "how" - specific methods used to achieve tactical goals
  - Format: `T####` (e.g., `T1543`)
  - Sub-techniques: `T####.###` (e.g., `T1543.003` for "Windows Service")

- **Procedures**: The specific implementations by threat actors

### Framework Purpose

- Standardizes attack classification across security tools
- Enables consistent threat intelligence sharing
- Provides common language for security teams
- Helps prioritize defenses based on observed adversary behavior

---

## Wazuh Alert Structure

### Complete Alert JSON Format

Wazuh alerts containing MITRE ATT&CK data follow this structure:

```json
{
  "agent": {
    "id": "002",
    "name": "Windows11",
    "ip": "172.20.10.3"
  },
  "manager": {
    "name": "wazuh-server"
  },
  "rule": {
    "id": "110011",
    "level": 10,
    "description": "PsExec service running as NT AUTHORITY\\SYSTEM has been created on Windows11",
    "groups": ["windows", "sysmon", "privilege-escalation"],
    "firedtimes": 4,
    "mail": false,
    "mitre": {
      "id": ["T1543.003"],
      "technique": ["Windows Service"],
      "tactic": ["Persistence", "Privilege Escalation"]
    }
  },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\system32\\services.exe",
        "targetObject": "HKLM\\System\\CurrentControlSet\\Services\\PSEXESVC\\ObjectName",
        "processGuid": "{45cd4aff-93d1-6501-0b00-000000000b00}",
        "processId": "720",
        "utcTime": "2023-10-16 12:12:15.759",
        "ruleName": "technique_id=T1543,technique_name=Service Creation",
        "details": "LocalSystem",
        "eventType": "SetValue",
        "user": "NT AUTHORITY\\SYSTEM"
      },
      "system": {
        "eventID": "13",
        "computer": "Windows11",
        "providerName": "Microsoft-Windows-Sysmon"
      }
    }
  },
  "location": "EventChannel",
  "decoder": {
    "name": "windows_eventchannel"
  },
  "id": "1694607138.3688437",
  "timestamp": "2023-10-16T12:12:18.684+0000"
}
```

### Key MITRE Fields

The `rule.mitre` object contains:

- **`id`** (array): MITRE technique IDs
- **`technique`** (array): Human-readable technique names
- **`tactic`** (array): Associated tactics (multiple tactics per technique)

**Important**: Arrays are parallel - `id[0]` corresponds to `technique[0]` and its tactics are in `tactic`.

---

## Data Flow Architecture

### 1. Alert Collection Flow

```
Wazuh Agents → Wazuh Manager → Alert Processing → MITRE Extraction → Database Storage
```

### 2. API Data Flow

```
Frontend Request → FastAPI Endpoint → Alert Aggregation → MITRE Mapping → JSON Response
```

### 3. Real-Time Alert Flow

```
Wazuh Alert → WebSocket Handler → MITRE Parser → Frontend Update → Visualization Refresh
```

### Architecture Diagram

```
┌─────────────────┐
│  Wazuh Agents   │
│  (Endpoints)    │
└────────┬────────┘
         │ Sysmon/Logs
         ▼
┌─────────────────┐
│ Wazuh Manager   │◄───── Rules with MITRE IDs
│  (Alert Gen.)   │       (/var/ossec/etc/rules/)
└────────┬────────┘
         │ Alerts JSON
         ▼
┌─────────────────┐
│   FastAPI       │
│  Backend API    │
│                 │
│ ┌─────────────┐ │
│ │MITRE Parser │ │
│ │& Aggregator │ │
│ └─────────────┘ │
└────────┬────────┘
         │ Mapped Data
         ▼
┌─────────────────┐
│   PostgreSQL    │
│   Database      │
│  - alerts       │
│  - mitre_map    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  React Frontend │
│  - Dashboard    │
│  - Visualizer   │
│  - Mapper       │
└─────────────────┘
```

---

## Backend API Requirements

### 1. Alert Retrieval Endpoints

#### GET `/api/mitre/alerts`

Retrieve alerts with MITRE mappings.

**Query Parameters**:
- `start_date` (ISO 8601): Filter from date
- `end_date` (ISO 8601): Filter to date
- `tactic` (string): Filter by tactic
- `severity` (string): Filter by severity level
- `agent_id` (string): Filter by agent
- `limit` (int): Results limit (default: 100)
- `offset` (int): Pagination offset

**Response**:
```json
{
  "success": true,
  "data": {
    "alerts": [
      {
        "id": "alert_uuid",
        "timestamp": "2024-10-04T12:30:00Z",
        "agent": {
          "id": "002",
          "name": "Windows11",
          "ip": "172.20.10.3"
        },
        "rule": {
          "id": "110011",
          "level": 10,
          "description": "PsExec service detected"
        },
        "mitre": {
          "id": "T1543.003",
          "technique": "Windows Service",
          "tactics": ["Persistence", "Privilege Escalation"]
        },
        "severity": "critical"
      }
    ],
    "total": 250,
    "page": 1
  }
}
```

#### GET `/api/mitre/techniques/summary`

Get aggregated technique statistics.

**Response**:
```json
{
  "success": true,
  "data": {
    "techniques": [
      {
        "id": "T1543.003",
        "name": "Windows Service",
        "tactics": ["Persistence", "Privilege Escalation"],
        "count": 45,
        "severity_breakdown": {
          "critical": 12,
          "high": 23,
          "medium": 10
        },
        "affected_agents": ["002", "003", "005"],
        "first_seen": "2024-09-15T08:00:00Z",
        "last_seen": "2024-10-04T12:30:00Z"
      }
    ],
    "total_techniques": 15,
    "total_alerts": 287
  }
}
```

#### GET `/api/mitre/tactics/distribution`

Get tactic distribution for visualization.

**Response**:
```json
{
  "success": true,
  "data": {
    "tactics": [
      {
        "name": "Persistence",
        "count": 89,
        "techniques": ["T1543.003", "T1547.001"],
        "severity_max": "critical"
      },
      {
        "name": "Privilege Escalation",
        "count": 67,
        "techniques": ["T1543.003", "T1055"],
        "severity_max": "high"
      }
    ]
  }
}
```

### 2. Log Import Endpoint

#### POST `/api/mitre/import`

Import and analyze log files for MITRE mapping.

**Request Body**:
```json
{
  "logs": "...", // Raw log content or JSON
  "format": "json", // json, ndjson, or raw
  "source": "wazuh"
}
```

**Response**:
```json
{
  "success": true,
  "data": {
    "processed": 150,
    "mapped": 48,
    "skipped": 102,
    "techniques_found": [
      {
        "id": "T1543.003",
        "count": 12
      }
    ]
  }
}
```

### 3. Real-Time WebSocket

#### WS `/ws/mitre/alerts`

Stream real-time MITRE-mapped alerts.

**Message Format**:
```json
{
  "type": "mitre_alert",
  "data": {
    "timestamp": "2024-10-04T12:30:00Z",
    "alert": { /* full alert object */ },
    "mitre": {
      "id": "T1543.003",
      "technique": "Windows Service",
      "tactics": ["Persistence", "Privilege Escalation"]
    }
  }
}
```

---

## Database Schema

### Table: `mitre_alerts`

Stores all security alerts with MITRE mappings.

```sql
CREATE TABLE mitre_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id VARCHAR(255) UNIQUE NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Agent Information
    agent_id VARCHAR(50) NOT NULL,
    agent_name VARCHAR(255),
    agent_ip INET,
    
    -- Rule Information
    rule_id VARCHAR(50) NOT NULL,
    rule_level INTEGER NOT NULL,
    rule_description TEXT NOT NULL,
    rule_groups TEXT[],
    
    -- MITRE ATT&CK Fields
    mitre_technique_id VARCHAR(20) NOT NULL, -- e.g., T1543.003
    mitre_technique_name VARCHAR(255) NOT NULL,
    mitre_tactics TEXT[] NOT NULL, -- Array of tactics
    
    -- Severity Classification
    severity VARCHAR(20) NOT NULL, -- critical, high, medium, low
    
    -- Raw Data
    raw_alert JSONB NOT NULL,
    event_data JSONB,
    
    -- Indexing
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT valid_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'))
);

-- Indexes for performance
CREATE INDEX idx_mitre_alerts_timestamp ON mitre_alerts(timestamp DESC);
CREATE INDEX idx_mitre_alerts_technique_id ON mitre_alerts(mitre_technique_id);
CREATE INDEX idx_mitre_alerts_tactics ON mitre_alerts USING GIN(mitre_tactics);
CREATE INDEX idx_mitre_alerts_agent ON mitre_alerts(agent_id);
CREATE INDEX idx_mitre_alerts_severity ON mitre_alerts(severity);
CREATE INDEX idx_mitre_alerts_rule_id ON mitre_alerts(rule_id);
```

### Table: `mitre_technique_stats`

Aggregated statistics for techniques (materialized view or updated via trigger).

```sql
CREATE TABLE mitre_technique_stats (
    technique_id VARCHAR(20) PRIMARY KEY,
    technique_name VARCHAR(255) NOT NULL,
    tactics TEXT[] NOT NULL,
    
    -- Statistics
    total_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    
    -- Timing
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    
    -- Affected Systems
    affected_agents TEXT[],
    
    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_technique_stats_count ON mitre_technique_stats(total_count DESC);
CREATE INDEX idx_technique_stats_last_seen ON mitre_technique_stats(last_seen DESC);
```

### Trigger: Update Stats on Alert Insert

```sql
CREATE OR REPLACE FUNCTION update_mitre_stats()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO mitre_technique_stats (
        technique_id,
        technique_name,
        tactics,
        total_count,
        critical_count,
        high_count,
        medium_count,
        low_count,
        first_seen,
        last_seen,
        affected_agents
    ) VALUES (
        NEW.mitre_technique_id,
        NEW.mitre_technique_name,
        NEW.mitre_tactics,
        1,
        CASE WHEN NEW.severity = 'critical' THEN 1 ELSE 0 END,
        CASE WHEN NEW.severity = 'high' THEN 1 ELSE 0 END,
        CASE WHEN NEW.severity = 'medium' THEN 1 ELSE 0 END,
        CASE WHEN NEW.severity = 'low' THEN 1 ELSE 0 END,
        NEW.timestamp,
        NEW.timestamp,
        ARRAY[NEW.agent_id]
    )
    ON CONFLICT (technique_id) DO UPDATE SET
        total_count = mitre_technique_stats.total_count + 1,
        critical_count = mitre_technique_stats.critical_count + 
            CASE WHEN NEW.severity = 'critical' THEN 1 ELSE 0 END,
        high_count = mitre_technique_stats.high_count + 
            CASE WHEN NEW.severity = 'high' THEN 1 ELSE 0 END,
        medium_count = mitre_technique_stats.medium_count + 
            CASE WHEN NEW.severity = 'medium' THEN 1 ELSE 0 END,
        low_count = mitre_technique_stats.low_count + 
            CASE WHEN NEW.severity = 'low' THEN 1 ELSE 0 END,
        last_seen = NEW.timestamp,
        affected_agents = array_append(
            CASE 
                WHEN NEW.agent_id = ANY(mitre_technique_stats.affected_agents) 
                THEN mitre_technique_stats.affected_agents
                ELSE array_append(mitre_technique_stats.affected_agents, NEW.agent_id)
            END,
            NULL -- Remove NULL values
        ),
        updated_at = NOW();
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_mitre_stats
AFTER INSERT ON mitre_alerts
FOR EACH ROW
EXECUTE FUNCTION update_mitre_stats();
```

---

## MITRE Mapping Logic

### Python Backend Implementation

#### 1. Alert Parser

```python
from typing import List, Dict, Optional
from datetime import datetime
from pydantic import BaseModel

class MitreData(BaseModel):
    id: List[str]
    technique: List[str]
    tactic: List[str]

class WazuhRule(BaseModel):
    id: str
    level: int
    description: str
    groups: List[str] = []
    mitre: Optional[MitreData] = None

class WazuhAgent(BaseModel):
    id: str
    name: str
    ip: Optional[str] = None

class WazuhAlert(BaseModel):
    agent: WazuhAgent
    rule: WazuhRule
    timestamp: str
    id: str
    data: Optional[Dict] = None

def parse_severity(rule_level: int) -> str:
    """
    Map Wazuh rule level to severity classification.
    
    Wazuh levels:
    - 0-3: Informational
    - 4-6: Low
    - 7-9: Medium
    - 10-12: High
    - 13-15: Critical
    """
    if rule_level >= 13:
        return "critical"
    elif rule_level >= 10:
        return "high"
    elif rule_level >= 7:
        return "medium"
    elif rule_level >= 4:
        return "low"
    else:
        return "info"

def extract_mitre_mappings(alert: WazuhAlert) -> List[Dict]:
    """
    Extract individual MITRE technique mappings from a Wazuh alert.
    
    Returns a list of mappings because one alert can have multiple techniques.
    """
    if not alert.rule.mitre or not alert.rule.mitre.id:
        return []
    
    mappings = []
    mitre = alert.rule.mitre
    
    # Parallel arrays: id[0] → technique[0]
    for i, technique_id in enumerate(mitre.id):
        technique_name = mitre.technique[i] if i < len(mitre.technique) else "Unknown"
        
        mapping = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactics": mitre.tactic,  # All tactics apply to all techniques
            "alert_id": alert.id,
            "timestamp": alert.timestamp,
            "agent_id": alert.agent.id,
            "agent_name": alert.agent.name,
            "agent_ip": alert.agent.ip,
            "rule_id": alert.rule.id,
            "rule_level": alert.rule.level,
            "rule_description": alert.rule.description,
            "severity": parse_severity(alert.rule.level),
            "raw_alert": alert.dict()
        }
        mappings.append(mapping)
    
    return mappings
```

#### 2. Database Service

```python
from typing import List, Dict, Optional
from datetime import datetime
import asyncpg

class MitreService:
    def __init__(self, db_pool: asyncpg.Pool):
        self.db = db_pool
    
    async def insert_alert(self, mapping: Dict) -> str:
        """Insert a MITRE-mapped alert into the database."""
        query = """
            INSERT INTO mitre_alerts (
                alert_id, timestamp, agent_id, agent_name, agent_ip,
                rule_id, rule_level, rule_description, rule_groups,
                mitre_technique_id, mitre_technique_name, mitre_tactics,
                severity, raw_alert, event_data
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
            )
            ON CONFLICT (alert_id) DO NOTHING
            RETURNING id
        """
        
        async with self.db.acquire() as conn:
            row = await conn.fetchrow(
                query,
                mapping["alert_id"],
                mapping["timestamp"],
                mapping["agent_id"],
                mapping["agent_name"],
                mapping["agent_ip"],
                mapping["rule_id"],
                mapping["rule_level"],
                mapping["rule_description"],
                mapping.get("rule_groups", []),
                mapping["technique_id"],
                mapping["technique_name"],
                mapping["tactics"],
                mapping["severity"],
                mapping["raw_alert"],
                mapping.get("event_data")
            )
            
            return str(row["id"]) if row else None
    
    async def get_technique_summary(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 50
    ) -> List[Dict]:
        """Get aggregated technique statistics."""
        query = """
            SELECT 
                technique_id,
                technique_name,
                tactics,
                total_count,
                critical_count,
                high_count,
                medium_count,
                low_count,
                first_seen,
                last_seen,
                affected_agents
            FROM mitre_technique_stats
            ORDER BY total_count DESC
            LIMIT $1
        """
        
        async with self.db.acquire() as conn:
            rows = await conn.fetch(query, limit)
            return [dict(row) for row in rows]
    
    async def get_tactic_distribution(self) -> List[Dict]:
        """Get distribution of tactics for visualization."""
        query = """
            SELECT 
                unnest(mitre_tactics) as tactic,
                COUNT(*) as count,
                MAX(severity) as max_severity
            FROM mitre_alerts
            WHERE timestamp >= NOW() - INTERVAL '30 days'
            GROUP BY tactic
            ORDER BY count DESC
        """
        
        async with self.db.acquire() as conn:
            rows = await conn.fetch(query)
            return [dict(row) for row in rows]
```

#### 3. FastAPI Endpoints

```python
from fastapi import APIRouter, Query, HTTPException
from typing import Optional
from datetime import datetime

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])

@router.get("/alerts")
async def get_mitre_alerts(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    tactic: Optional[str] = None,
    severity: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Retrieve alerts with MITRE mappings."""
    # Build dynamic query based on filters
    conditions = ["1=1"]
    params = []
    
    if start_date:
        params.append(datetime.fromisoformat(start_date))
        conditions.append(f"timestamp >= ${len(params)}")
    
    if end_date:
        params.append(datetime.fromisoformat(end_date))
        conditions.append(f"timestamp <= ${len(params)}")
    
    if tactic:
        params.append(tactic)
        conditions.append(f"${len(params)} = ANY(mitre_tactics)")
    
    if severity:
        params.append(severity)
        conditions.append(f"severity = ${len(params)}")
    
    if agent_id:
        params.append(agent_id)
        conditions.append(f"agent_id = ${len(params)}")
    
    params.extend([limit, offset])
    
    query = f"""
        SELECT * FROM mitre_alerts
        WHERE {' AND '.join(conditions)}
        ORDER BY timestamp DESC
        LIMIT ${len(params)-1} OFFSET ${len(params)}
    """
    
    # Execute query and return results
    # ... (database execution logic)

@router.get("/techniques/summary")
async def get_technique_summary(
    limit: int = Query(50, ge=1, le=200)
):
    """Get aggregated technique statistics."""
    service = MitreService(db_pool)
    return await service.get_technique_summary(limit=limit)

@router.get("/tactics/distribution")
async def get_tactic_distribution():
    """Get tactic distribution for visualization."""
    service = MitreService(db_pool)
    return await service.get_tactic_distribution()

@router.post("/import")
async def import_logs(
    logs: str,
    format: str = "json",
    source: str = "wazuh"
):
    """Import and analyze logs for MITRE mapping."""
    # Parse logs based on format
    if format == "json":
        alerts = json.loads(logs)
    elif format == "ndjson":
        alerts = [json.loads(line) for line in logs.split("\n") if line.strip()]
    else:
        raise HTTPException(400, "Unsupported format")
    
    # Process each alert
    processed = 0
    mapped = 0
    
    for alert_data in alerts:
        alert = WazuhAlert(**alert_data)
        mappings = extract_mitre_mappings(alert)
        
        if mappings:
            for mapping in mappings:
                await service.insert_alert(mapping)
                mapped += 1
        
        processed += 1
    
    return {
        "success": True,
        "data": {
            "processed": processed,
            "mapped": mapped,
            "skipped": processed - mapped
        }
    }
```

---

## Visualization Best Practices

### 1. Tactic Heatmap

Display the frequency of each tactic over time:

```typescript
// Frontend visualization data structure
interface TacticHeatmapData {
  tactic: string;
  timeRange: string; // e.g., "2024-10-01"
  count: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
}
```

### 2. Technique Timeline

Show technique occurrences over time:

```typescript
interface TechniqueTimelineData {
  timestamp: string;
  technique_id: string;
  technique_name: string;
  count: number;
  affected_agents: string[];
}
```

### 3. Attack Kill Chain Visualization

Map techniques to attack phases:

```typescript
const ATTACK_PHASES = [
  { name: "Initial Access", tactics: ["Initial Access"] },
  { name: "Execution", tactics: ["Execution"] },
  { name: "Persistence", tactics: ["Persistence", "Privilege Escalation"] },
  { name: "Lateral Movement", tactics: ["Lateral Movement", "Discovery"] },
  { name: "Exfiltration", tactics: ["Collection", "Exfiltration"] },
  { name: "Impact", tactics: ["Impact"] }
];
```

### 4. Smart Features for GUI

**Contextual Information**:
- Link technique IDs to official MITRE ATT&CK pages
- Show affected systems and recommended mitigations
- Display related techniques and threat actor groups

**Intelligent Filtering**:
- Filter by time range (last 24h, 7 days, 30 days, custom)
- Filter by severity (critical, high, medium, low)
- Filter by tactic or technique
- Filter by agent/system

**Aggregation Views**:
- Top 10 most frequent techniques
- Most targeted systems
- Severity distribution
- Tactic coverage (which tactics are being targeted)

**Drill-Down Capability**:
- Click technique → view all related alerts
- Click agent → view all techniques detected on that system
- Click tactic → view all associated techniques

---

## Integration with Reporting System

### AI Report Generation Prompts

The MITRE data should be included in AI-generated reports with proper context:

```python
def build_mitre_report_context(
    techniques: List[Dict],
    tactics: List[Dict],
    time_range: str
) -> str:
    """Build MITRE ATT&CK context for AI report generation."""
    
    context = f"""
    ## MITRE ATT&CK Analysis ({time_range})
    
    ### Detected Techniques
    """
    
    for tech in techniques[:10]:  # Top 10
        context += f"""
    - **{tech['technique_id']} - {tech['technique_name']}**
      - Occurrences: {tech['total_count']}
      - Tactics: {', '.join(tech['tactics'])}
      - Severity Breakdown: {tech['critical_count']} critical, {tech['high_count']} high
      - Affected Systems: {', '.join(tech['affected_agents'])}
    """
    
    context += """
    
    ### Tactic Distribution
    """
    
    for tactic in tactics:
        context += f"- {tactic['name']}: {tactic['count']} occurrences\n"
    
    return context

# Usage in report generation
mitre_context = build_mitre_report_context(techniques, tactics, "Last 30 Days")

# Include in LLM prompt
system_prompt = f"""
You are a cybersecurity analyst generating a threat intelligence report.
Analyze the following MITRE ATT&CK data and provide:
1. Executive summary of attack patterns
2. Most critical threats identified
3. Recommended defensive measures
4. Trend analysis

{mitre_context}

Generate a professional report suitable for {audience_type}.
"""
```

### Report Sections

1. **Executive Summary**: High-level overview of MITRE tactics and critical techniques
2. **Threat Landscape**: Distribution of tactics and attack patterns
3. **Technique Analysis**: Deep dive into most frequent techniques
4. **Affected Systems**: Which systems are being targeted
5. **Recommendations**: Based on detected TTPs, suggest defensive measures
6. **Threat Actor Correlation**: If patterns match known threat groups

---

## Testing and Validation

### Unit Tests

```python
import pytest
from datetime import datetime

def test_parse_severity():
    assert parse_severity(15) == "critical"
    assert parse_severity(10) == "high"
    assert parse_severity(7) == "medium"
    assert parse_severity(4) == "low"
    assert parse_severity(2) == "info"

def test_extract_mitre_mappings():
    alert = WazuhAlert(
        agent=WazuhAgent(id="002", name="Windows11", ip="172.20.10.3"),
        rule=WazuhRule(
            id="110011",
            level=10,
            description="PsExec detected",
            mitre=MitreData(
                id=["T1543.003"],
                technique=["Windows Service"],
                tactic=["Persistence", "Privilege Escalation"]
            )
        ),
        timestamp="2024-10-04T12:30:00Z",
        id="alert_123"
    )
    
    mappings = extract_mitre_mappings(alert)
    
    assert len(mappings) == 1
    assert mappings[0]["technique_id"] == "T1543.003"
    assert mappings[0]["severity"] == "high"
    assert "Persistence" in mappings[0]["tactics"]
```

### Integration Tests

```python
@pytest.mark.asyncio
async def test_insert_and_retrieve_alert(db_pool):
    service = MitreService(db_pool)
    
    mapping = {
        "alert_id": "test_alert_001",
        "timestamp": datetime.now(),
        "agent_id": "002",
        "agent_name": "TestAgent",
        "agent_ip": "192.168.1.100",
        "rule_id": "110011",
        "rule_level": 10,
        "rule_description": "Test rule",
        "technique_id": "T1543.003",
        "technique_name": "Windows Service",
        "tactics": ["Persistence"],
        "severity": "high",
        "raw_alert": {}
    }
    
    alert_id = await service.insert_alert(mapping)
    assert alert_id is not None
    
    # Verify stats were updated
    stats = await service.get_technique_summary(limit=1)
    assert len(stats) > 0
    assert stats[0]["technique_id"] == "T1543.003"
```

---

## Best Practices Summary

### Do's ✅

1. **Always validate MITRE data exists** before processing
2. **Handle missing fields gracefully** (technique name, tactics)
3. **Use parallel arrays correctly** (id[i] → technique[i])
4. **Aggregate data for performance** (use stats tables)
5. **Provide drill-down capabilities** (click to see details)
6. **Link to official MITRE resources** (mitre.org/attack/)
7. **Include temporal analysis** (trends over time)
8. **Correlate with threat intelligence** (known threat actors)
9. **Use proper severity mapping** (Wazuh level → severity)
10. **Cache frequently accessed data** (technique summaries)

### Don'ts ❌

1. **Don't assume all alerts have MITRE data** (many don't)
2. **Don't ignore null/empty fields** (graceful degradation)
3. **Don't query full alert table for stats** (use aggregated tables)
4. **Don't expose raw internal IDs** to users (use technique IDs)
5. **Don't hardcode tactic/technique lists** (they evolve)
6. **Don't skip validation** (malformed data can break parsing)
7. **Don't ignore timezones** (always use UTC)
8. **Don't overload the UI** (paginate large datasets)

---

## References

- [MITRE ATT&CK Framework Official Website](https://attack.mitre.org/)
- [Wazuh MITRE ATT&CK Integration Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html)
- [Wazuh Rule Syntax Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/rules/index.html)
- [MITRE ATT&CK API](https://github.com/mitre-attack/attack-stix-data)

---

## Appendix: Complete Tactic & Technique Reference

### 14 MITRE ATT&CK Tactics

1. **Reconnaissance** (TA0043): Gathering information about targets
2. **Resource Development** (TA0042): Establishing resources to support operations
3. **Initial Access** (TA0001): Getting into the network
4. **Execution** (TA0002): Running malicious code
5. **Persistence** (TA0003): Maintaining presence
6. **Privilege Escalation** (TA0004): Gaining higher-level permissions
7. **Defense Evasion** (TA0005): Avoiding detection
8. **Credential Access** (TA0006): Stealing credentials
9. **Discovery** (TA0007): Exploring the environment
10. **Lateral Movement** (TA0008): Moving through the network
11. **Collection** (TA0009): Gathering data of interest
12. **Command and Control** (TA0011): Communicating with compromised systems
13. **Exfiltration** (TA0010): Stealing data
14. **Impact** (TA0040): Manipulating, interrupting, or destroying systems

### Common Techniques by Tactic

**Initial Access**:
- T1078: Valid Accounts
- T1190: Exploit Public-Facing Application
- T1566: Phishing

**Execution**:
- T1059: Command and Scripting Interpreter
- T1569: System Services
- T1204: User Execution

**Persistence**:
- T1543: Create or Modify System Process
  - T1543.003: Windows Service (like our example)
- T1053: Scheduled Task/Job
- T1547: Boot or Logon Autostart Execution

**Privilege Escalation**:
- T1068: Exploitation for Privilege Escalation
- T1055: Process Injection
- T1134: Access Token Manipulation

---

**Document Version**: 1.0  
**Last Updated**: 2024-10-04  
**Maintained By**: Security Operations Team
