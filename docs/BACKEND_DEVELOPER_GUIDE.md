# Backend Developer Guide for Security Testing Platform

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [API Design Patterns](#api-design-patterns)
3. [Real-time Communication](#real-time-communication)
4. [Security Tool Integrations](#security-tool-integrations)
5. [OSINT Automation](#osint-automation)
6. [Implementation Examples](#implementation-examples)
7. [Security Considerations](#security-considerations)
8. [Deployment and Scaling](#deployment-and-scaling)
9. [Best Practices](#best-practices)

## Architecture Overview

### System Components

The backend architecture for the security testing platform consists of several interconnected services:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend UI   │    │  API Gateway    │    │   Tool Engine   │
│                 │◄──►│                 │◄──►│                 │
│ React/WebSocket │    │  FastAPI/REST   │    │ Docker/Podman   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐             │
         │              │   Session Mgr   │             │
         └──────────────►│                 │◄────────────┘
                        │ Redis/PostgreSQL│
                        └─────────────────┘
                                 │
                        ┌─────────────────┐
                        │   AI Agent      │
                        │                 │
                        │  LLM/Perplexity │
                        └─────────────────┘
```

### Core Services

1. **API Gateway**: FastAPI-based REST API with WebSocket support
2. **Session Manager**: Handles pentest session lifecycle and state
3. **Tool Engine**: Containerized security tool execution environment
4. **AI Agent**: Intelligent decision-making and automation
5. **OSINT Agent**: Encrypted intelligence gathering service

## API Design Patterns

### RESTful API Structure

Based on research from penetration testing automation frameworks, the API follows these patterns:

```python
# FastAPI Application Structure
from fastapi import FastAPI, WebSocket, Depends
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from typing import Dict, List, Optional

app = FastAPI(
    title="Security Testing Platform API",
    version="2.0.0",
    description="Advanced penetration testing and OSINT automation"
)

# Session Management
@app.post("/api/v2/pentest/sessions")
async def create_session(config: PentestSessionConfig):
    """Create new penetration test session"""
    session = await session_manager.create_session(config)
    return {"session_id": session.id, "status": "created"}

@app.get("/api/v2/pentest/sessions/{session_id}/status")
async def get_session_status(session_id: str):
    """Get real-time session status"""
    session = await session_manager.get_session(session_id)
    return {
        "session_id": session_id,
        "status": session.status,
        "progress": session.progress,
        "findings": session.findings,
        "tools_executed": session.tools_executed
    }

# Tool Execution Endpoints
@app.post("/api/v2/tools/{tool_name}/execute")
async def execute_tool(
    tool_name: str,
    config: ToolConfig,
    session_id: str = Depends(get_current_session)
):
    """Execute security tool with configuration"""
    execution_id = await tool_engine.execute_tool(
        tool_name=tool_name,
        config=config,
        session_id=session_id
    )
    return {"execution_id": execution_id, "status": "started"}
```

### WebSocket Real-time Updates

```python
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, session_id: str):
        await websocket.accept()
        if session_id not in self.active_connections:
            self.active_connections[session_id] = []
        self.active_connections[session_id].append(websocket)
    
    async def broadcast_to_session(self, session_id: str, message: dict):
        if session_id in self.active_connections:
            for connection in self.active_connections[session_id]:
                try:
                    await connection.send_json(message)
                except:
                    await self.disconnect(connection, session_id)

manager = ConnectionManager()

@app.websocket("/ws/session/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    await manager.connect(websocket, session_id)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            # Process client messages if needed
    except WebSocketDisconnect:
        await manager.disconnect(websocket, session_id)
```

## Real-time Communication

### Terminal Output Streaming

Based on analysis of penetration testing frameworks like Kali MCP Server and APT-TS:

```python
import asyncio
import subprocess
from asyncio.subprocess import PIPE

class TerminalExecutor:
    def __init__(self, session_manager, websocket_manager):
        self.session_manager = session_manager
        self.websocket_manager = websocket_manager
    
    async def execute_command(self, session_id: str, command: str, tool: str):
        """Execute command and stream output in real-time"""
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=PIPE,
                stderr=PIPE,
                text=True
            )
            
            # Stream stdout
            async for line in self._read_stream(process.stdout):
                await self._send_terminal_output(
                    session_id, line, "stdout", tool
                )
            
            # Stream stderr
            async for line in self._read_stream(process.stderr):
                await self._send_terminal_output(
                    session_id, line, "stderr", tool
                )
            
            await process.wait()
            return process.returncode
            
        except Exception as e:
            await self._send_terminal_output(
                session_id, f"Error: {str(e)}", "error", tool
            )
    
    async def _read_stream(self, stream):
        while True:
            line = await stream.readline()
            if not line:
                break
            yield line.decode().rstrip()
    
    async def _send_terminal_output(self, session_id, content, output_type, tool):
        message = {
            "type": "terminal_output",
            "session_id": session_id,
            "content": content,
            "output_type": output_type,
            "tool": tool,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.websocket_manager.broadcast_to_session(session_id, message)
```

### Progress Tracking

```python
class ProgressTracker:
    def __init__(self):
        self.session_progress: Dict[str, float] = {}
    
    async def update_progress(self, session_id: str, tool: str, progress: float):
        """Update and broadcast progress information"""
        if session_id not in self.session_progress:
            self.session_progress[session_id] = {}
        
        self.session_progress[session_id][tool] = progress
        
        # Calculate overall session progress
        total_progress = sum(self.session_progress[session_id].values())
        tool_count = len(self.session_progress[session_id])
        overall_progress = total_progress / tool_count if tool_count > 0 else 0
        
        await self.websocket_manager.broadcast_to_session(session_id, {
            "type": "progress_update",
            "session_id": session_id,
            "tool": tool,
            "tool_progress": progress,
            "overall_progress": overall_progress
        })
```

## Security Tool Integrations

### Docker-based Tool Execution

Based on research from container security tools and kdigger implementation:

```python
import docker
import tempfile
import json
from pathlib import Path

class SecurityToolEngine:
    def __init__(self):
        self.docker_client = docker.from_env()
        self.tool_configs = {
            "nmap": {
                "image": "instrumentisto/nmap:latest",
                "capabilities": ["NET_RAW", "NET_ADMIN"],
                "network_mode": "host"
            },
            "kdigger": {
                "image": "quarkslab/kdigger:latest",
                "volumes": {
                    "/var/run/docker.sock": "/var/run/docker.sock",
                    "/proc": "/host/proc:ro",
                    "/sys": "/host/sys:ro"
                }
            },
            "bloodhound": {
                "image": "bloodhoundad/bloodhound:latest",
                "environment": ["NEO4J_AUTH=neo4j/bloodhound"]
            }
        }
    
    async def execute_nmap(self, session_id: str, config: NmapConfig):
        """Execute Nmap scan with configuration"""
        command_args = self._build_nmap_command(config)
        
        container = self.docker_client.containers.run(
            image=self.tool_configs["nmap"]["image"],
            command=command_args,
            detach=True,
            remove=True,
            cap_add=self.tool_configs["nmap"]["capabilities"],
            network_mode=self.tool_configs["nmap"]["network_mode"]
        )
        
        # Stream container logs
        for log in container.logs(stream=True, follow=True):
            await self._process_tool_output(
                session_id, log.decode(), "nmap"
            )
    
    def _build_nmap_command(self, config: NmapConfig) -> List[str]:
        """Build Nmap command from configuration"""
        cmd = ["nmap"]
        
        # Add flags based on configuration
        if config.syn_scan:
            cmd.append("-sS")
        if config.service_detection:
            cmd.append("-sV")
        if config.os_detection:
            cmd.append("-O")
        if config.aggressive:
            cmd.append("-A")
        
        # Add port specification
        if config.ports:
            cmd.extend(["-p", config.ports])
        
        # Add timing template
        if config.timing:
            cmd.extend(["-T", str(config.timing)])
        
        # Add output format
        if config.output_file:
            cmd.extend(["-oA", config.output_file])
        
        # Add target
        cmd.append(config.target)
        
        return cmd
```

### Kubernetes Security Assessment

Based on kube-hunter and kdigger research:

```python
class KubernetesSecurityEngine:
    async def execute_kube_hunter(self, session_id: str, config: KubeHunterConfig):
        """Execute kube-hunter security assessment"""
        
        # Prepare kube-hunter configuration
        kh_config = {
            "remote": config.remote_targets,
            "interface": config.network_interface,
            "pod": config.pod_mode,
            "active": config.active_hunting,
            "report": config.report_format
        }
        
        # Build command
        cmd = ["kube-hunter"]
        if config.remote_targets:
            cmd.extend(["--remote", ",".join(config.remote_targets)])
        if config.active_hunting:
            cmd.append("--active")
        if config.report_format:
            cmd.extend(["--report", config.report_format])
        
        # Execute in container
        container = self.docker_client.containers.run(
            image="aquasec/kube-hunter:latest",
            command=cmd,
            detach=True,
            remove=True,
            network_mode="host"
        )
        
        # Process results
        for log in container.logs(stream=True, follow=True):
            await self._process_k8s_findings(session_id, log.decode())
    
    async def execute_kdigger(self, session_id: str, config: KdiggerConfig):
        """Execute kdigger context discovery"""
        
        # Mount necessary host paths for container analysis
        volumes = {
            "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"},
            "/proc": {"bind": "/host/proc", "mode": "ro"},
            "/sys": {"bind": "/host/sys", "mode": "ro"},
            "/etc": {"bind": "/host/etc", "mode": "ro"}
        }
        
        cmd = ["kdigger"]
        if config.runtime_analysis:
            cmd.append("runtime")
        if config.network_analysis:
            cmd.append("network")
        if config.dig_mode:
            cmd.append("dig")
        
        container = self.docker_client.containers.run(
            image="quarkslab/kdigger:latest",
            command=cmd,
            detach=True,
            remove=True,
            volumes=volumes,
            privileged=True  # Required for container escape detection
        )
        
        await self._stream_container_output(container, session_id, "kdigger")
```

### Active Directory Assessment

Based on BloodHound Community Edition and CrackMapExec research:

```python
class ActiveDirectoryEngine:
    async def execute_bloodhound(self, session_id: str, config: BloodHoundConfig):
        """Execute BloodHound data collection"""
        
        # Prepare SharpHound collector
        collector_config = {
            "CollectionMethods": config.collection_methods,
            "Domain": config.domain,
            "LdapUsername": config.ldap_username,
            "LdapPassword": config.ldap_password,
            "Stealth": config.stealth_mode,
            "ExcludeDCs": config.exclude_dcs
        }
        
        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(collector_config, f)
            config_path = f.name
        
        # Execute SharpHound in Wine container
        cmd = [
            "wine", "SharpHound.exe",
            "-c", config.collection_methods,
            "-d", config.domain
        ]
        
        if config.stealth_mode:
            cmd.append("--stealth")
        if config.ldap_username:
            cmd.extend(["--ldapusername", config.ldap_username])
        if config.ldap_password:
            cmd.extend(["--ldappassword", config.ldap_password])
        
        container = self.docker_client.containers.run(
            image="bloodhoundad/sharphound:latest",
            command=cmd,
            detach=True,
            remove=True,
            volumes={config_path: {"bind": "/config.json", "mode": "ro"}}
        )
        
        await self._stream_container_output(container, session_id, "bloodhound")
    
    async def execute_crackmapexec(self, session_id: str, config: CrackMapExecConfig):
        """Execute CrackMapExec lateral movement testing"""
        
        cmd = ["crackmapexec", config.protocol]
        cmd.append(config.target)
        
        # Authentication
        if config.username:
            cmd.extend(["-u", config.username])
        if config.password:
            cmd.extend(["-p", config.password])
        elif config.ntlm_hash:
            cmd.extend(["-H", config.ntlm_hash])
        
        # Enumeration options
        if config.enumerate_shares:
            cmd.append("--shares")
        if config.enumerate_users:
            cmd.append("--users")
        if config.dump_sam:
            cmd.append("--sam")
        if config.dump_lsa:
            cmd.append("--lsa")
        
        # Threading and timing
        cmd.extend(["--threads", str(config.threads)])
        
        container = self.docker_client.containers.run(
            image="byt3bl33d3r/crackmapexec:latest",
            command=cmd,
            detach=True,
            remove=True,
            network_mode="host"
        )
        
        await self._stream_container_output(container, session_id, "crackmapexec")
```

## OSINT Automation

### Encrypted OSINT Agent

Based on research from Blue Helix Agentic OSINT and multi-agent systems:

```python
import aiohttp
import asyncio
from cryptography.fernet import Fernet
from typing import Dict, List, Any

class EncryptedOSINTAgent:
    def __init__(self, encryption_key: str, perplexity_api_key: str):
        self.cipher = Fernet(encryption_key.encode())
        self.perplexity_api_key = perplexity_api_key
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def research_target(self, target: str, research_type: str) -> Dict[str, Any]:
        """Conduct automated OSINT research on target"""
        
        # Encrypt target information
        encrypted_target = self.cipher.encrypt(target.encode())
        
        research_queries = self._generate_research_queries(target, research_type)
        results = {}
        
        for category, queries in research_queries.items():
            category_results = []
            for query in queries:
                try:
                    result = await self._perplexity_search(query)
                    category_results.append({
                        "query": query,
                        "result": result,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                except Exception as e:
                    category_results.append({
                        "query": query,
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat()
                    })
            
            results[category] = category_results
        
        return {
            "target": target,
            "research_type": research_type,
            "results": results,
            "encrypted": True
        }
    
    def _generate_research_queries(self, target: str, research_type: str) -> Dict[str, List[str]]:
        """Generate OSINT research queries based on target and type"""
        
        base_queries = {
            "domain_intelligence": [
                f"site:{target} filetype:pdf",
                f"site:{target} inurl:login",
                f"site:{target} inurl:admin",
                f"\"{target}\" vulnerability disclosure",
                f"\"{target}\" security breach data leak"
            ],
            "infrastructure": [
                f"\"{target}\" IP address ranges",
                f"\"{target}\" ASN autonomous system",
                f"\"{target}\" DNS records subdomains",
                f"\"{target}\" cloud infrastructure AWS Azure",
                f"\"{target}\" CDN content delivery network"
            ],
            "social_engineering": [
                f"\"{target}\" employees LinkedIn directory",
                f"\"{target}\" email format pattern",
                f"\"{target}\" organizational chart structure",
                f"\"{target}\" recent news announcements",
                f"\"{target}\" social media presence"
            ],
            "threat_intelligence": [
                f"\"{target}\" CVE vulnerability reports",
                f"\"{target}\" exploit code github",
                f"\"{target}\" security advisories",
                f"\"{target}\" malware analysis reports",
                f"\"{target}\" threat actor mentions"
            ]
        }
        
        if research_type == "comprehensive":
            return base_queries
        else:
            return {research_type: base_queries.get(research_type, [])}
    
    async def _perplexity_search(self, query: str) -> Dict[str, Any]:
        """Execute search using Perplexity API"""
        
        payload = {
            "model": "llama-3.1-sonar-large-128k-online",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity OSINT analyst. Provide precise, factual intelligence with sources. Focus on publicly available information only."
                },
                {
                    "role": "user",
                    "content": f"Research and analyze: {query}"
                }
            ],
            "temperature": 0.2,
            "top_p": 0.9,
            "max_tokens": 1000,
            "return_images": False,
            "return_related_questions": True,
            "search_domain_filter": [
                "github.com", "cve.mitre.org", "nvd.nist.gov",
                "exploit-db.com", "packetstormsecurity.com"
            ],
            "search_recency_filter": "month",
            "frequency_penalty": 1,
            "presence_penalty": 0
        }
        
        headers = {
            "Authorization": f"Bearer {self.perplexity_api_key}",
            "Content-Type": "application/json"
        }
        
        async with self.session.post(
            "https://api.perplexity.ai/chat/completions",
            json=payload,
            headers=headers
        ) as response:
            if response.status == 200:
                data = await response.json()
                return {
                    "answer": data["choices"][0]["message"]["content"],
                    "sources": data.get("citations", []),
                    "related_questions": data.get("related_questions", [])
                }
            else:
                raise Exception(f"Perplexity API error: {response.status}")
```

## AI-Driven Automation

### Intelligent Decision Engine

```python
import openai
from typing import Dict, List, Any, Optional

class IntelligentPentestAgent:
    def __init__(self, llm_provider: str, api_key: str, model: str = "gpt-4"):
        self.llm_provider = llm_provider
        self.api_key = api_key
        self.model = model
        self.client = openai.OpenAI(api_key=api_key) if llm_provider == "openai" else None
    
    async def analyze_findings_and_recommend(self, findings: List[Dict], execution_history: List[Dict]) -> Dict[str, Any]:
        """Analyze current findings and recommend next actions"""
        
        context = self._build_analysis_context(findings, execution_history)
        
        system_prompt = """
        You are an expert penetration tester and AI agent. Analyze the current findings and execution history to recommend the most effective next steps.
        
        Consider:
        1. Severity and exploitability of findings
        2. Attack path progression opportunities  
        3. Lateral movement possibilities
        4. Privilege escalation vectors
        5. Risk vs. reward of each technique
        
        Respond with JSON containing:
        - next_steps: array of recommended actions
        - priority: high/medium/low
        - reasoning: explanation of recommendations
        - techniques: specific techniques to use
        - tools: recommended tools for execution
        """
        
        user_prompt = f"""
        Current Assessment Context:
        
        FINDINGS:
        {json.dumps(findings, indent=2)}
        
        EXECUTION HISTORY:
        {json.dumps(execution_history, indent=2)}
        
        Based on this information, what should be the next steps for maximum impact while maintaining stealth?
        """
        
        response = await self._llm_request(system_prompt, user_prompt)
        
        try:
            recommendations = json.loads(response)
            return recommendations
        except json.JSONDecodeError:
            return {
                "next_steps": ["Continue enumeration"],
                "priority": "medium",
                "reasoning": "Unable to parse AI response, defaulting to safe actions",
                "techniques": ["reconnaissance"],
                "tools": ["nmap"]
            }
    
    async def _llm_request(self, system_prompt: str, user_prompt: str) -> str:
        """Make request to configured LLM provider"""
        
        if self.llm_provider == "openai":
            response = await self.client.chat.completions.acreate(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )
            return response.choices[0].message.content
        
        # Add other providers as needed
        else:
            raise ValueError(f"Unsupported LLM provider: {self.llm_provider}")
```

## Security Considerations

### Secure Tool Execution

```python
import os
import pwd
import grp
from pathlib import Path

class SecureToolExecutor:
    def __init__(self):
        self.allowed_tools = {
            "nmap", "nikto", "sqlmap", "bloodhound", 
            "crackmapexec", "kdigger", "kube-hunter"
        }
        self.restricted_networks = [
            "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
        ]
    
    def validate_tool_execution(self, tool_name: str, config: Dict) -> bool:
        """Validate tool execution for security"""
        
        # Check if tool is allowed
        if tool_name not in self.allowed_tools:
            raise SecurityError(f"Tool {tool_name} not in allowed list")
        
        # Validate target is not internal network (unless explicitly allowed)
        target = config.get("target")
        if target and not config.get("allow_internal", False):
            if self._is_internal_target(target):
                raise SecurityError(f"Internal target {target} requires explicit permission")
        
        return True

class SecurityError(Exception):
    pass
```

## Best Practices

### 1. Security-First Design
- **Principle of Least Privilege**: Run tools with minimal required permissions
- **Network Segmentation**: Isolate tool execution environment
- **Input Validation**: Sanitize all user inputs and tool configurations
- **Audit Logging**: Log all tool executions and findings

### 2. Scalability Patterns
- **Async Processing**: Use async/await for I/O operations
- **Background Tasks**: Use Celery or similar for long-running tool executions  
- **Caching**: Cache tool results and configurations with Redis
- **Load Balancing**: Distribute tool execution across multiple workers

### 3. Error Handling and Resilience
```python
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential

class ResilientToolExecutor:
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def execute_tool_with_retry(self, tool_name: str, config: Dict):
        """Execute tool with automatic retry logic"""
        try:
            return await self.tool_engine.execute_tool(tool_name, config)
        except ToolExecutionError as e:
            if e.is_retryable():
                raise e  # Retry
            else:
                return {"error": str(e), "retryable": False}
```

This comprehensive backend developer guide provides the foundation for implementing a production-ready security testing platform with real-time capabilities, AI automation, and encrypted OSINT functionality.