# Third-Party Integrations Guide

## Overview

This document provides comprehensive guidance for integrating third-party security tools and libraries into the IPS Security Center FastAPI backend. It covers security considerations, implementation patterns, and best practices for managing external dependencies.

## Security Tools Integration

### 1. Wazuh SIEM Integration

#### Overview
Wazuh is an open-source security monitoring platform that provides intrusion detection, vulnerability assessment, and compliance monitoring.

#### Integration Architecture
```python
# app/integrations/wazuh.py
from typing import Dict, Any, List, Optional
import httpx
import asyncio
from datetime import datetime, timedelta
import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()

class WazuhConfig(BaseModel):
    base_url: str = Field(..., description="Wazuh API base URL")
    api_key: str = Field(..., description="Wazuh API key")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    max_retries: int = Field(default=3, description="Maximum retry attempts")

class WazuhAgent(BaseModel):
    id: str
    name: str
    ip: str
    status: str
    os_platform: str
    os_version: str
    version: str
    last_keepalive: datetime
    node_name: str
    date_add: datetime

class WazuhAlert(BaseModel):
    id: str
    timestamp: datetime
    rule_id: str
    rule_level: int
    rule_description: str
    agent_id: str
    agent_name: str
    location: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    full_log: str

class WazuhIntegration:
    def __init__(self, config: WazuhConfig):
        self.config = config
        self.client = httpx.AsyncClient(
            timeout=config.timeout,
            verify=config.verify_ssl,
            headers={
                "Authorization": f"Bearer {config.api_key}",
                "Content-Type": "application/json"
            }
        )
        self._health_status = None
        self._last_health_check = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Wazuh API health and connectivity"""
        try:
            response = await self.client.get(f"{self.config.base_url}/")
            response.raise_for_status()
            
            data = response.json()
            self._health_status = "healthy"
            self._last_health_check = datetime.utcnow()
            
            return {
                "status": "healthy",
                "service": "wazuh",
                "version": data.get("data", {}).get("api_version"),
                "response_time": response.elapsed.total_seconds(),
                "timestamp": self._last_health_check.isoformat()
            }
        except Exception as e:
            self._health_status = "unhealthy"
            self._last_health_check = datetime.utcnow()
            logger.error("Wazuh health check failed", error=str(e))
            
            return {
                "status": "unhealthy",
                "service": "wazuh",
                "error": str(e),
                "timestamp": self._last_health_check.isoformat()
            }
    
    async def get_agents(self, 
                        limit: int = 100, 
                        offset: int = 0,
                        status: Optional[str] = None,
                        search: Optional[str] = None) -> List[WazuhAgent]:
        """Retrieve Wazuh agents with filtering"""
        params = {
            "limit": limit,
            "offset": offset,
            "sort": "+id"
        }
        
        if status:
            params["status"] = status
        if search:
            params["search"] = search
        
        try:
            response = await self.client.get(
                f"{self.config.base_url}/agents",
                params=params
            )
            response.raise_for_status()
            
            data = response.json()
            agents = []
            
            for agent_data in data.get("data", {}).get("affected_items", []):
                agents.append(WazuhAgent(
                    id=agent_data["id"],
                    name=agent_data["name"],
                    ip=agent_data["ip"],
                    status=agent_data["status"],
                    os_platform=agent_data.get("os", {}).get("platform", ""),
                    os_version=agent_data.get("os", {}).get("version", ""),
                    version=agent_data.get("version", ""),
                    last_keepalive=datetime.fromisoformat(
                        agent_data["lastKeepAlive"].replace("Z", "+00:00")
                    ),
                    node_name=agent_data.get("node_name", ""),
                    date_add=datetime.fromisoformat(
                        agent_data["dateAdd"].replace("Z", "+00:00")
                    )
                ))
            
            return agents
            
        except Exception as e:
            logger.error("Failed to get Wazuh agents", error=str(e))
            raise
    
    async def get_alerts(self,
                        limit: int = 100,
                        offset: int = 0,
                        severity_min: Optional[int] = None,
                        agent_id: Optional[str] = None,
                        time_range: Optional[str] = "24h") -> List[WazuhAlert]:
        """Retrieve Wazuh alerts with filtering"""
        params = {
            "limit": limit,
            "offset": offset,
            "sort": "-timestamp"
        }
        
        if severity_min:
            params["rule.level"] = f">={severity_min}"
        if agent_id:
            params["agent.id"] = agent_id
        if time_range:
            params["timestamp"] = self._parse_time_range(time_range)
        
        try:
            response = await self.client.get(
                f"{self.config.base_url}/security_events",
                params=params
            )
            response.raise_for_status()
            
            data = response.json()
            alerts = []
            
            for alert_data in data.get("data", {}).get("affected_items", []):
                alerts.append(WazuhAlert(
                    id=alert_data.get("id", ""),
                    timestamp=datetime.fromisoformat(
                        alert_data["timestamp"].replace("Z", "+00:00")
                    ),
                    rule_id=alert_data["rule"]["id"],
                    rule_level=alert_data["rule"]["level"],
                    rule_description=alert_data["rule"]["description"],
                    agent_id=alert_data["agent"]["id"],
                    agent_name=alert_data["agent"]["name"],
                    location=alert_data.get("location", ""),
                    source_ip=alert_data.get("data", {}).get("srcip"),
                    destination_ip=alert_data.get("data", {}).get("dstip"),
                    full_log=alert_data.get("full_log", "")
                ))
            
            return alerts
            
        except Exception as e:
            logger.error("Failed to get Wazuh alerts", error=str(e))
            raise
    
    def _parse_time_range(self, time_range: str) -> str:
        """Convert time range to Wazuh timestamp format"""
        now = datetime.utcnow()
        
        if time_range.endswith('h'):
            hours = int(time_range[:-1])
            start_time = now - timedelta(hours=hours)
        elif time_range.endswith('d'):
            days = int(time_range[:-1])
            start_time = now - timedelta(days=days)
        elif time_range.endswith('m'):
            minutes = int(time_range[:-1])
            start_time = now - timedelta(minutes=minutes)
        else:
            start_time = now - timedelta(hours=24)
        
        return f">={start_time.isoformat()}Z"
```

#### Best Practices
1. **Connection Pooling**: Use `httpx.AsyncClient` with connection limits
2. **Circuit Breaker**: Implement circuit breaker pattern for resilience
3. **Rate Limiting**: Respect Wazuh API rate limits
4. **Caching**: Cache frequently accessed data with appropriate TTL
5. **Error Handling**: Implement comprehensive error handling and logging

### 2. OpenVAS/GVM Integration

#### Overview
Greenbone Vulnerability Management (GVM) is a comprehensive vulnerability assessment and management framework.

#### Integration Implementation
```python
# app/integrations/gvm.py
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
import httpx
import asyncio
from datetime import datetime, timedelta
import base64
import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()

class GVMConfig(BaseModel):
    base_url: str = Field(..., description="GVM API base URL")
    username: str = Field(..., description="GVM username")
    password: str = Field(..., description="GVM password")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    timeout: int = Field(default=60, description="Request timeout in seconds")

class GVMTarget(BaseModel):
    id: str
    name: str
    hosts: List[str]
    port_list: str
    alive_test: str
    created: datetime
    modified: datetime

class GVMScan(BaseModel):
    id: str
    name: str
    target_id: str
    config_id: str
    status: str
    progress: int
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

class GVMVulnerability(BaseModel):
    id: str
    name: str
    severity: float
    host: str
    port: str
    nvt_oid: str
    description: str
    solution: str
    references: List[str]

class GVMIntegration:
    def __init__(self, config: GVMConfig):
        self.config = config
        self.client = httpx.AsyncClient(
            timeout=config.timeout,
            verify=config.verify_ssl
        )
        self._session_token = None
        self._authenticated = False
    
    async def __aenter__(self):
        await self.authenticate()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    async def authenticate(self) -> bool:
        """Authenticate with GVM and obtain session token"""
        auth_xml = f"""
        <authenticate>
            <credentials>
                <username>{self.config.username}</username>
                <password>{self.config.password}</password>
            </credentials>
        </authenticate>
        """
        
        try:
            response = await self.client.post(
                f"{self.config.base_url}/gmp",
                content=auth_xml,
                headers={"Content-Type": "application/xml"}
            )
            response.raise_for_status()
            
            root = ET.fromstring(response.text)
            status = root.get("status")
            
            if status == "200":
                self._session_token = root.get("id")
                self._authenticated = True
                logger.info("GVM authentication successful")
                return True
            else:
                logger.error("GVM authentication failed", status=status)
                return False
                
        except Exception as e:
            logger.error("GVM authentication error", error=str(e))
            return False
    
    async def health_check(self) -> Dict[str, Any]:
        """Check GVM service health"""
        try:
            if not self._authenticated:
                await self.authenticate()
            
            version_xml = "<get_version/>"
            response = await self._send_gmp_command(version_xml)
            
            if response:
                return {
                    "status": "healthy",
                    "service": "gvm",
                    "version": response.get("version"),
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                return {
                    "status": "unhealthy",
                    "service": "gvm",
                    "error": "Failed to get version",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error("GVM health check failed", error=str(e))
            return {
                "status": "unhealthy",
                "service": "gvm",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def get_targets(self) -> List[GVMTarget]:
        """Get all configured targets"""
        targets_xml = "<get_targets/>"
        
        try:
            response = await self._send_gmp_command(targets_xml)
            targets = []
            
            if response and "targets" in response:
                for target_data in response["targets"]:
                    targets.append(GVMTarget(
                        id=target_data["id"],
                        name=target_data["name"],
                        hosts=target_data["hosts"].split(","),
                        port_list=target_data.get("port_list", ""),
                        alive_test=target_data.get("alive_test", ""),
                        created=datetime.fromisoformat(target_data["creation_time"]),
                        modified=datetime.fromisoformat(target_data["modification_time"])
                    ))
            
            return targets
            
        except Exception as e:
            logger.error("Failed to get GVM targets", error=str(e))
            raise
    
    async def create_target(self, name: str, hosts: List[str], 
                           port_list_id: str = None) -> str:
        """Create a new scan target"""
        hosts_str = ",".join(hosts)
        
        target_xml = f"""
        <create_target>
            <name>{name}</name>
            <hosts>{hosts_str}</hosts>
            {f'<port_list id="{port_list_id}"/>' if port_list_id else ''}
        </create_target>
        """
        
        try:
            response = await self._send_gmp_command(target_xml)
            
            if response and response.get("status") == "201":
                return response.get("id")
            else:
                raise Exception(f"Failed to create target: {response}")
                
        except Exception as e:
            logger.error("Failed to create GVM target", error=str(e))
            raise
    
    async def start_scan(self, name: str, target_id: str, 
                        config_id: str = None) -> str:
        """Start a vulnerability scan"""
        # Use default Full and fast scan config if none provided
        if not config_id:
            config_id = "daba56c8-73ec-11df-a475-002264764cea"
        
        task_xml = f"""
        <create_task>
            <name>{name}</name>
            <target id="{target_id}"/>
            <config id="{config_id}"/>
        </create_task>
        """
        
        try:
            # Create task
            response = await self._send_gmp_command(task_xml)
            
            if response and response.get("status") == "201":
                task_id = response.get("id")
                
                # Start task
                start_xml = f'<start_task task_id="{task_id}"/>'
                start_response = await self._send_gmp_command(start_xml)
                
                if start_response and start_response.get("status") == "202":
                    return task_id
                else:
                    raise Exception(f"Failed to start scan: {start_response}")
            else:
                raise Exception(f"Failed to create task: {response}")
                
        except Exception as e:
            logger.error("Failed to start GVM scan", error=str(e))
            raise
    
    async def get_scan_results(self, task_id: str) -> List[GVMVulnerability]:
        """Get scan results for a task"""
        results_xml = f'<get_results task_id="{task_id}"/>'
        
        try:
            response = await self._send_gmp_command(results_xml)
            vulnerabilities = []
            
            if response and "results" in response:
                for result in response["results"]:
                    vulnerabilities.append(GVMVulnerability(
                        id=result["id"],
                        name=result["name"],
                        severity=float(result.get("severity", 0)),
                        host=result.get("host", ""),
                        port=result.get("port", ""),
                        nvt_oid=result.get("nvt", {}).get("oid", ""),
                        description=result.get("description", ""),
                        solution=result.get("solution", ""),
                        references=result.get("references", [])
                    ))
            
            return vulnerabilities
            
        except Exception as e:
            logger.error("Failed to get GVM scan results", error=str(e))
            raise
    
    async def _send_gmp_command(self, xml_command: str) -> Dict[str, Any]:
        """Send GMP XML command to GVM"""
        if not self._authenticated:
            await self.authenticate()
        
        headers = {
            "Content-Type": "application/xml",
            "Cookie": f"token={self._session_token}" if self._session_token else ""
        }
        
        try:
            response = await self.client.post(
                f"{self.config.base_url}/gmp",
                content=xml_command,
                headers=headers
            )
            response.raise_for_status()
            
            # Parse XML response
            root = ET.fromstring(response.text)
            return self._xml_to_dict(root)
            
        except Exception as e:
            logger.error("GMP command failed", command=xml_command, error=str(e))
            raise
    
    def _xml_to_dict(self, element) -> Dict[str, Any]:
        """Convert XML element to dictionary"""
        result = {}
        
        # Add attributes
        if element.attrib:
            result.update(element.attrib)
        
        # Add text content
        if element.text and element.text.strip():
            result["text"] = element.text.strip()
        
        # Add child elements
        for child in element:
            child_data = self._xml_to_dict(child)
            
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
        
        return result
```

### 3. OWASP ZAP Integration

#### Overview
OWASP ZAP (Zed Attack Proxy) is a web application security scanner for finding vulnerabilities in web applications.

#### Integration Implementation
```python
# app/integrations/zap.py
from typing import Dict, Any, List, Optional
import httpx
import asyncio
from datetime import datetime, timedelta
import json
import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()

class ZAPConfig(BaseModel):
    base_url: str = Field(..., description="ZAP API base URL")
    api_key: str = Field(..., description="ZAP API key")
    timeout: int = Field(default=300, description="Request timeout in seconds")

class ZAPScanConfig(BaseModel):
    target_url: str
    scan_type: str = Field(default="baseline", description="baseline, full, api")
    spider_enabled: bool = Field(default=True)
    active_scan_enabled: bool = Field(default=True)
    max_duration: int = Field(default=3600, description="Max scan duration in seconds")
    context_name: Optional[str] = None
    exclude_urls: List[str] = Field(default_factory=list)

class ZAPAlert(BaseModel):
    id: str
    alert: str
    risk: str
    confidence: str
    url: str
    param: str
    method: str
    evidence: str
    description: str
    solution: str
    reference: str
    cwe_id: Optional[int] = None
    wasc_id: Optional[int] = None

class ZAPIntegration:
    def __init__(self, config: ZAPConfig):
        self.config = config
        self.client = httpx.AsyncClient(timeout=config.timeout)
        self._base_params = {"apikey": config.api_key}
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    async def health_check(self) -> Dict[str, Any]:
        """Check ZAP service health"""
        try:
            response = await self.client.get(
                f"{self.config.base_url}/JSON/core/view/version/",
                params=self._base_params
            )
            response.raise_for_status()
            
            data = response.json()
            
            return {
                "status": "healthy",
                "service": "zap",
                "version": data.get("version"),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error("ZAP health check failed", error=str(e))
            return {
                "status": "unhealthy",
                "service": "zap",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def start_scan(self, scan_config: ZAPScanConfig) -> str:
        """Start a web application scan"""
        scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Create new session
            await self._create_session(scan_id)
            
            # Configure context if needed
            if scan_config.context_name:
                await self._create_context(scan_config.context_name, scan_config.target_url)
            
            # Add exclude URLs
            for exclude_url in scan_config.exclude_urls:
                await self._exclude_url(exclude_url)
            
            # Start spider if enabled
            if scan_config.spider_enabled:
                spider_id = await self._start_spider(scan_config.target_url)
                await self._wait_for_spider(spider_id)
            
            # Start active scan if enabled
            if scan_config.active_scan_enabled:
                ascan_id = await self._start_active_scan(scan_config.target_url)
                # Don't wait for active scan completion, return scan ID immediately
                
                return scan_id
            else:
                return scan_id
                
        except Exception as e:
            logger.error("Failed to start ZAP scan", error=str(e))
            raise
    
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan progress and status"""
        try:
            # Get spider status
            spider_status = await self._get_spider_status()
            
            # Get active scan status
            ascan_status = await self._get_active_scan_status()
            
            # Get current alerts count
            alerts = await self.get_alerts()
            
            return {
                "scan_id": scan_id,
                "spider": spider_status,
                "active_scan": ascan_status,
                "alerts_count": len(alerts),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error("Failed to get ZAP scan status", error=str(e), scan_id=scan_id)
            raise
    
    async def get_alerts(self, base_url: Optional[str] = None) -> List[ZAPAlert]:
        """Get scan alerts/vulnerabilities"""
        params = self._base_params.copy()
        if base_url:
            params["baseurl"] = base_url
        
        try:
            response = await self.client.get(
                f"{self.config.base_url}/JSON/core/view/alerts/",
                params=params
            )
            response.raise_for_status()
            
            data = response.json()
            alerts = []
            
            for alert_data in data.get("alerts", []):
                alerts.append(ZAPAlert(
                    id=str(alert_data.get("id", "")),
                    alert=alert_data.get("alert", ""),
                    risk=alert_data.get("risk", ""),
                    confidence=alert_data.get("confidence", ""),
                    url=alert_data.get("url", ""),
                    param=alert_data.get("param", ""),
                    method=alert_data.get("method", ""),
                    evidence=alert_data.get("evidence", ""),
                    description=alert_data.get("description", ""),
                    solution=alert_data.get("solution", ""),
                    reference=alert_data.get("reference", ""),
                    cwe_id=int(alert_data["cweid"]) if alert_data.get("cweid") else None,
                    wasc_id=int(alert_data["wascid"]) if alert_data.get("wascid") else None
                ))
            
            return alerts
            
        except Exception as e:
            logger.error("Failed to get ZAP alerts", error=str(e))
            raise
    
    async def generate_report(self, scan_id: str, format: str = "json") -> Dict[str, Any]:
        """Generate scan report"""
        try:
            if format.lower() == "html":
                response = await self.client.get(
                    f"{self.config.base_url}/OTHER/core/other/htmlreport/",
                    params=self._base_params
                )
            elif format.lower() == "xml":
                response = await self.client.get(
                    f"{self.config.base_url}/OTHER/core/other/xmlreport/",
                    params=self._base_params
                )
            else:  # JSON format
                alerts = await self.get_alerts()
                return {
                    "scan_id": scan_id,
                    "generated_at": datetime.utcnow().isoformat(),
                    "alerts": [alert.dict() for alert in alerts]
                }
            
            response.raise_for_status()
            
            return {
                "scan_id": scan_id,
                "format": format,
                "content": response.text,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error("Failed to generate ZAP report", error=str(e), scan_id=scan_id)
            raise
    
    async def _create_session(self, session_name: str):
        """Create new ZAP session"""
        params = self._base_params.copy()
        params["name"] = session_name
        
        response = await self.client.get(
            f"{self.config.base_url}/JSON/core/action/newSession/",
            params=params
        )
        response.raise_for_status()
    
    async def _create_context(self, context_name: str, target_url: str):
        """Create scan context"""
        params = self._base_params.copy()
        params["contextName"] = context_name
        
        response = await self.client.get(
            f"{self.config.base_url}/JSON/context/action/newContext/",
            params=params
        )
        response.raise_for_status()
        
        # Include URL in context
        include_params = self._base_params.copy()
        include_params.update({
            "contextName": context_name,
            "regex": f"{target_url}.*"
        })
        
        await self.client.get(
            f"{self.config.base_url}/JSON/context/action/includeInContext/",
            params=include_params
        )
    
    async def _exclude_url(self, url_pattern: str):
        """Exclude URL pattern from scan"""
        params = self._base_params.copy()
        params["regex"] = url_pattern
        
        response = await self.client.get(
            f"{self.config.base_url}/JSON/core/action/excludeFromProxy/",
            params=params
        )
        response.raise_for_status()
    
    async def _start_spider(self, target_url: str) -> str:
        """Start spider scan"""
        params = self._base_params.copy()
        params["url"] = target_url
        
        response = await self.client.get(
            f"{self.config.base_url}/JSON/spider/action/scan/",
            params=params
        )
        response.raise_for_status()
        
        data = response.json()
        return data.get("scan", "")
    
    async def _wait_for_spider(self, spider_id: str, timeout: int = 300):
        """Wait for spider to complete"""
        start_time = datetime.utcnow()
        
        while (datetime.utcnow() - start_time).total_seconds() < timeout:
            status = await self._get_spider_status()
            
            if status.get("status") == "100":
                break
                
            await asyncio.sleep(5)
    
    async def _get_spider_status(self) -> Dict[str, Any]:
        """Get spider scan status"""
        response = await self.client.get(
            f"{self.config.base_url}/JSON/spider/view/status/",
            params=self._base_params
        )
        response.raise_for_status()
        
        return response.json()
    
    async def _start_active_scan(self, target_url: str) -> str:
        """Start active scan"""
        params = self._base_params.copy()
        params["url"] = target_url
        
        response = await self.client.get(
            f"{self.config.base_url}/JSON/ascan/action/scan/",
            params=params
        )
        response.raise_for_status()
        
        data = response.json()
        return data.get("scan", "")
    
    async def _get_active_scan_status(self) -> Dict[str, Any]:
        """Get active scan status"""
        response = await self.client.get(
            f"{self.config.base_url}/JSON/ascan/view/status/",
            params=self._base_params
        )
        response.raise_for_status()
        
        return response.json()
```

### 4. SpiderFoot Integration

#### Overview
SpiderFoot is an open-source intelligence (OSINT) automation tool for reconnaissance and threat intelligence gathering.

#### Integration Implementation
```python
# app/integrations/spiderfoot.py
from typing import Dict, Any, List, Optional
import httpx
import asyncio
from datetime import datetime, timedelta
import json
import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()

class SpiderFootConfig(BaseModel):
    base_url: str = Field(..., description="SpiderFoot API base URL")
    api_key: Optional[str] = Field(None, description="SpiderFoot API key")
    timeout: int = Field(default=60, description="Request timeout in seconds")

class SpiderFootScanConfig(BaseModel):
    name: str
    target: str
    target_type: str = Field(default="domain", description="domain, ip, email, etc.")
    modules: List[str] = Field(default_factory=list)
    scan_options: Dict[str, Any] = Field(default_factory=dict)

class SpiderFootResult(BaseModel):
    id: str
    scan_id: str
    module: str
    element: str
    element_type: str
    source: str
    confidence: int
    visibility: str
    risk: str
    created: datetime
    data: str

class SpiderFootIntegration:
    def __init__(self, config: SpiderFootConfig):
        self.config = config
        headers = {}
        if config.api_key:
            headers["Authorization"] = f"Bearer {config.api_key}"
        
        self.client = httpx.AsyncClient(
            timeout=config.timeout,
            headers=headers
        )
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    async def health_check(self) -> Dict[str, Any]:
        """Check SpiderFoot service health"""
        try:
            response = await self.client.get(f"{self.config.base_url}/")
            
            if response.status_code == 200:
                return {
                    "status": "healthy",
                    "service": "spiderfoot",
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                return {
                    "status": "unhealthy",
                    "service": "spiderfoot",
                    "error": f"HTTP {response.status_code}",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error("SpiderFoot health check failed", error=str(e))
            return {
                "status": "unhealthy",
                "service": "spiderfoot",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def get_modules(self) -> List[Dict[str, Any]]:
        """Get available SpiderFoot modules"""
        try:
            response = await self.client.get(f"{self.config.base_url}/modules")
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            logger.error("Failed to get SpiderFoot modules", error=str(e))
            raise
    
    async def start_scan(self, scan_config: SpiderFootScanConfig) -> str:
        """Start OSINT reconnaissance scan"""
        scan_data = {
            "scanname": scan_config.name,
            "scantarget": scan_config.target,
            "targettype": scan_config.target_type,
            "modulelist": ",".join(scan_config.modules) if scan_config.modules else "",
            "typelist": "",  # Use all data types by default
            "usecase": "all"
        }
        
        # Add scan options
        scan_data.update(scan_config.scan_options)
        
        try:
            response = await self.client.post(
                f"{self.config.base_url}/startscan",
                data=scan_data
            )
            response.raise_for_status()
            
            result = response.json()
            scan_id = result.get("id")
            
            if scan_id:
                logger.info("SpiderFoot scan started", scan_id=scan_id, target=scan_config.target)
                return scan_id
            else:
                raise Exception("Failed to get scan ID from response")
                
        except Exception as e:
            logger.error("Failed to start SpiderFoot scan", error=str(e))
            raise
    
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status and progress"""
        try:
            response = await self.client.get(f"{self.config.base_url}/scansummary/{scan_id}")
            response.raise_for_status()
            
            data = response.json()
            
            return {
                "scan_id": scan_id,
                "status": data.get("status", "unknown"),
                "started": data.get("started"),
                "ended": data.get("ended"),
                "elements_found": data.get("found", 0),
                "modules_run": data.get("modules", 0),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error("Failed to get SpiderFoot scan status", error=str(e), scan_id=scan_id)
            raise
    
    async def get_scan_results(self, scan_id: str, 
                              element_type: Optional[str] = None) -> List[SpiderFootResult]:
        """Get scan results"""
        url = f"{self.config.base_url}/scaneventresults/{scan_id}"
        params = {}
        
        if element_type:
            params["eventType"] = element_type
        
        try:
            response = await self.client.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            results = []
            
            for result_data in data:
                results.append(SpiderFootResult(
                    id=result_data[0],
                    scan_id=scan_id,
                    module=result_data[1] or "",
                    element=result_data[2] or "",
                    element_type=result_data[3] or "",
                    source=result_data[4] or "",
                    confidence=int(result_data[5] or 0),
                    visibility=result_data[6] or "",
                    risk=result_data[7] or "",
                    created=datetime.fromtimestamp(float(result_data[8] or 0) / 1000),
                    data=result_data[9] or ""
                ))
            
            return results
            
        except Exception as e:
            logger.error("Failed to get SpiderFoot scan results", error=str(e), scan_id=scan_id)
            raise
    
    async def get_scan_logs(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get scan execution logs"""
        try:
            response = await self.client.get(f"{self.config.base_url}/scanlog/{scan_id}")
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            logger.error("Failed to get SpiderFoot scan logs", error=str(e), scan_id=scan_id)
            raise
    
    async def stop_scan(self, scan_id: str) -> bool:
        """Stop running scan"""
        try:
            response = await self.client.get(f"{self.config.base_url}/stopscan/{scan_id}")
            response.raise_for_status()
            
            result = response.json()
            return result.get("status") == "OK"
            
        except Exception as e:
            logger.error("Failed to stop SpiderFoot scan", error=str(e), scan_id=scan_id)
            raise
    
    async def delete_scan(self, scan_id: str) -> bool:
        """Delete scan and its results"""
        try:
            response = await self.client.get(f"{self.config.base_url}/deletescan/{scan_id}")
            response.raise_for_status()
            
            result = response.json()
            return result.get("status") == "OK"
            
        except Exception as e:
            logger.error("Failed to delete SpiderFoot scan", error=str(e), scan_id=scan_id)
            raise
```

## Integration Management Service

### Unified Integration Manager
```python
# app/services/integration_manager.py
from typing import Dict, Any, List, Optional
import asyncio
from datetime import datetime, timedelta
import structlog
from contextlib import asynccontextmanager

from app.integrations.wazuh import WazuhIntegration, WazuhConfig
from app.integrations.gvm import GVMIntegration, GVMConfig
from app.integrations.zap import ZAPIntegration, ZAPConfig
from app.integrations.spiderfoot import SpiderFootIntegration, SpiderFootConfig
from app.core.config import settings

logger = structlog.get_logger()

class IntegrationManager:
    def __init__(self):
        self.integrations = {}
        self._health_cache = {}
        self._health_cache_ttl = 300  # 5 minutes
        
        # Initialize integrations
        if settings.WAZUH_API_URL and settings.WAZUH_API_KEY:
            self.integrations["wazuh"] = WazuhIntegration(
                WazuhConfig(
                    base_url=settings.WAZUH_API_URL,
                    api_key=settings.WAZUH_API_KEY
                )
            )
        
        if settings.GVM_API_URL and settings.GVM_USERNAME and settings.GVM_PASSWORD:
            self.integrations["gvm"] = GVMIntegration(
                GVMConfig(
                    base_url=settings.GVM_API_URL,
                    username=settings.GVM_USERNAME,
                    password=settings.GVM_PASSWORD
                )
            )
        
        if settings.ZAP_API_URL and settings.ZAP_API_KEY:
            self.integrations["zap"] = ZAPIntegration(
                ZAPConfig(
                    base_url=settings.ZAP_API_URL,
                    api_key=settings.ZAP_API_KEY
                )
            )
        
        if settings.SPIDERFOOT_API_URL:
            self.integrations["spiderfoot"] = SpiderFootIntegration(
                SpiderFootConfig(
                    base_url=settings.SPIDERFOOT_API_URL,
                    api_key=settings.SPIDERFOOT_API_KEY
                )
            )
    
    @asynccontextmanager
    async def get_integration(self, service_name: str):
        """Get integration with context manager for proper cleanup"""
        if service_name not in self.integrations:
            raise ValueError(f"Integration '{service_name}' not configured")
        
        integration = self.integrations[service_name]
        
        try:
            async with integration as service:
                yield service
        except Exception as e:
            logger.error(f"Integration error for {service_name}", error=str(e))
            raise
    
    async def check_all_health(self, use_cache: bool = True) -> Dict[str, Any]:
        """Check health of all configured integrations"""
        now = datetime.utcnow()
        
        # Check cache if enabled
        if use_cache and self._health_cache:
            cache_time = self._health_cache.get("timestamp")
            if cache_time and (now - cache_time).total_seconds() < self._health_cache_ttl:
                return self._health_cache["data"]
        
        health_results = {}
        
        # Run health checks in parallel
        health_tasks = []
        for service_name, integration in self.integrations.items():
            health_tasks.append(self._check_service_health(service_name, integration))
        
        if health_tasks:
            results = await asyncio.gather(*health_tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                service_name = list(self.integrations.keys())[i]
                
                if isinstance(result, Exception):
                    health_results[service_name] = {
                        "status": "error",
                        "error": str(result),
                        "timestamp": now.isoformat()
                    }
                else:
                    health_results[service_name] = result
        
        # Determine overall status
        overall_status = "healthy"
        if not health_results:
            overall_status = "no_services"
        elif any(service.get("status") != "healthy" for service in health_results.values()):
            overall_status = "degraded"
        
        result = {
            "overall_status": overall_status,
            "services": health_results,
            "timestamp": now.isoformat()
        }
        
        # Update cache
        self._health_cache = {
            "data": result,
            "timestamp": now
        }
        
        return result
    
    async def _check_service_health(self, service_name: str, integration) -> Dict[str, Any]:
        """Check health of a specific service"""
        try:
            async with integration as service:
                return await service.health_check()
        except Exception as e:
            logger.error(f"Health check failed for {service_name}", error=str(e))
            return {
                "status": "unhealthy",
                "service": service_name,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def get_configured_services(self) -> List[str]:
        """Get list of configured integration services"""
        return list(self.integrations.keys())
    
    def is_service_configured(self, service_name: str) -> bool:
        """Check if a service is configured"""
        return service_name in self.integrations

# Global integration manager instance
integration_manager = IntegrationManager()
```

## Security Best Practices

### 1. Credential Management
- Store API keys and secrets in environment variables or secure vault
- Use different credentials for different environments
- Implement credential rotation mechanisms
- Never log credentials or sensitive data

### 2. Error Handling
- Implement comprehensive error handling for all integrations
- Use structured logging for troubleshooting
- Sanitize error messages before returning to clients
- Implement circuit breaker pattern for failing services

### 3. Rate Limiting
- Respect third-party API rate limits
- Implement exponential backoff for retries
- Use connection pooling for efficient resource usage
- Monitor API usage and costs

### 4. Data Privacy
- Minimize data collection and storage
- Implement data retention policies
- Anonymize or pseudonymize sensitive data
- Comply with relevant privacy regulations (GDPR, CCPA)

### 5. Network Security
- Use TLS for all communications
- Validate SSL certificates
- Implement network timeouts
- Use secure network configurations

This comprehensive integration guide provides the foundation for securely connecting with third-party security tools while maintaining proper security practices and error handling.