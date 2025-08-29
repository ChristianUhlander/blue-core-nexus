# IPS Security Center - Technical Architecture Documentation

## Overview

The IPS Security Center is a comprehensive security management platform that integrates multiple security tools including Wazuh, OpenVAS/GVM, OWASP ZAP, and SpiderFoot. This document outlines the current architecture and provides a roadmap for migration to a FastAPI backend.

## Current Architecture

### Frontend (React + TypeScript)
- **Framework**: React 18 with TypeScript
- **Styling**: Tailwind CSS with custom design system
- **State Management**: React hooks and context
- **Build Tool**: Vite
- **UI Components**: Radix UI + shadcn/ui
- **Routing**: React Router v6

### Key Components Structure
```
src/
├── components/
│   ├── ui/                    # Reusable UI components (shadcn)
│   ├── SecurityDashboard.tsx  # Main dashboard component
│   ├── AgenticPentestInterface.tsx
│   ├── GVMManagement.tsx
│   ├── WazuhManagement.tsx
│   └── IppsYChatPane.tsx      # AI chat interface
├── services/
│   ├── securityApi.ts         # Core security API client
│   ├── pentaguardApi.ts       # Pentaguard backend integration
│   ├── k8sPentestApi.ts       # Kubernetes pentest API
│   ├── k8sSecurityApi.ts      # K8s security services
│   └── agenticPentestApi.ts   # AI pentest integration
├── hooks/
│   ├── useSecurityStatus.ts   # Security status management
│   └── useRealTimeSecurityData.ts # Real-time data hooks
└── types/
    ├── security.ts            # Security-related types
    ├── penetration.ts         # Penetration testing types
    └── agenticPentest.ts      # AI pentest types
```

## Current Service Integrations

### 1. Wazuh SIEM Integration
- **Purpose**: Host-based intrusion detection, log analysis, file integrity monitoring
- **API Endpoints**: REST API for agents, alerts, rules management
- **Real-time**: WebSocket connection for live alerts
- **Authentication**: API key-based

### 2. OpenVAS/GVM Integration
- **Purpose**: Vulnerability assessment and management
- **API Endpoints**: XML-RPC and REST APIs for scan management
- **Features**: Target creation, scan configuration, report generation
- **Authentication**: Username/password with session management

### 3. OWASP ZAP Integration
- **Purpose**: Web application security testing
- **API Endpoints**: REST API for proxy, spider, active scan
- **Features**: Baseline scans, full scans, API testing
- **Authentication**: API key-based

### 4. SpiderFoot Integration
- **Purpose**: OSINT reconnaissance and threat intelligence
- **API Endpoints**: REST API for scan management
- **Features**: Domain reconnaissance, threat intelligence gathering
- **Authentication**: API key-based

## Current Security Concerns

### Critical Issues Identified
1. **Hardcoded Credentials**: API keys and secrets in client-side code
2. **Direct Service Access**: Frontend directly accessing internal security services
3. **No Authentication Layer**: Missing user authentication and authorization
4. **Insecure WebSocket**: Unencrypted real-time communications
5. **CORS Vulnerabilities**: Overly permissive CORS policies
6. **Input Validation**: Lack of comprehensive input sanitization

### Performance Issues
1. **Large Bundle Size**: Monolithic components causing slow load times
2. **Inefficient State Management**: No centralized state management
3. **Memory Leaks**: Unclosed WebSocket connections and intervals
4. **No Caching**: Repeated API calls without caching mechanisms

## Technology Stack Analysis

### Current Frontend Dependencies
- **Core**: React 18, TypeScript, Vite
- **UI**: Tailwind CSS, Radix UI, shadcn/ui
- **HTTP Client**: Fetch API with custom wrappers
- **WebSocket**: Native WebSocket API
- **State**: React hooks (useState, useEffect, useContext)
- **Routing**: React Router v6
- **Forms**: React Hook Form with Zod validation

### Recommended Backend Stack (FastAPI)
- **Framework**: FastAPI 0.104+
- **Authentication**: FastAPI-Users with JWT
- **Database**: PostgreSQL with SQLAlchemy 2.0
- **WebSocket**: FastAPI WebSocket with Redis pub/sub
- **Security**: Pydantic for validation, CORS middleware
- **Documentation**: OpenAPI 3.1 auto-generation
- **Testing**: pytest with async support
- **Deployment**: Docker with Kubernetes

## Migration Strategy

### Phase 1: Backend Foundation (Week 1-2)
1. **FastAPI Setup**
   ```python
   # Project structure
   backend/
   ├── app/
   │   ├── core/
   │   │   ├── config.py      # Configuration management
   │   │   ├── security.py    # JWT, CORS, auth
   │   │   └── database.py    # Database connection
   │   ├── api/
   │   │   ├── v1/
   │   │   │   ├── auth.py    # Authentication endpoints
   │   │   │   ├── security.py # Security tool endpoints
   │   │   │   └── websocket.py # Real-time endpoints
   │   ├── services/
   │   │   ├── security_integration.py
   │   │   ├── wazuh_service.py
   │   │   ├── gvm_service.py
   │   │   ├── zap_service.py
   │   │   └── spiderfoot_service.py
   │   ├── models/
   │   │   ├── user.py        # User models
   │   │   ├── security.py    # Security models
   │   │   └── scan.py        # Scan models
   │   └── schemas/
   │       ├── security.py    # Pydantic schemas
   │       └── user.py        # User schemas
   ├── requirements.txt
   ├── Dockerfile
   └── docker-compose.yml
   ```

### Phase 2: Service Migration (Week 3-4)
1. **Security Service Layer**
   - Implement service adapters for each security tool
   - Add circuit breaker pattern for resilience
   - Implement request/response caching
   - Add comprehensive logging and monitoring

### Phase 3: Authentication & Authorization (Week 5)
1. **User Management**
   - JWT-based authentication
   - Role-based access control (RBAC)
   - API key management for external integrations
   - Session management

### Phase 4: Real-time Features (Week 6)
1. **WebSocket Implementation**
   - Secure WebSocket authentication
   - Redis pub/sub for scaling
   - Message queuing and persistence
   - Connection management

## API Design Specifications

### Authentication Endpoints
```python
POST /api/v1/auth/login
POST /api/v1/auth/logout
POST /api/v1/auth/refresh
GET  /api/v1/auth/me
```

### Security Tool Endpoints
```python
# Wazuh
GET    /api/v1/wazuh/agents
GET    /api/v1/wazuh/alerts
POST   /api/v1/wazuh/agents/{agent_id}/restart

# GVM/OpenVAS
GET    /api/v1/gvm/targets
POST   /api/v1/gvm/scans
GET    /api/v1/gvm/scans/{scan_id}/report

# OWASP ZAP
POST   /api/v1/zap/scans
GET    /api/v1/zap/scans/{scan_id}/status
GET    /api/v1/zap/scans/{scan_id}/report

# SpiderFoot
POST   /api/v1/spiderfoot/scans
GET    /api/v1/spiderfoot/scans/{scan_id}/results
```

### WebSocket Endpoints
```python
WS /api/v1/ws/security-alerts  # Real-time security alerts
WS /api/v1/ws/scan-progress    # Scan progress updates
WS /api/v1/ws/system-status    # System health updates
```

## Security Implementation

### Authentication Strategy
```python
from fastapi_users import FastAPIUsers
from fastapi_users.authentication import JWTAuthentication

# JWT Configuration
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Role-based permissions
class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
```

### Security Middleware
```python
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-frontend-domain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Trusted Host Middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["your-domain.com", "*.your-domain.com"]
)
```

## Database Schema Design

### Core Tables
```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Security tools configuration
CREATE TABLE security_tools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL, -- wazuh, gvm, zap, spiderfoot
    endpoint VARCHAR(255) NOT NULL,
    api_key VARCHAR(255),
    config JSONB,
    status VARCHAR(20) DEFAULT 'inactive',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Scan results
CREATE TABLE scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    tool_type VARCHAR(50) NOT NULL,
    target VARCHAR(255) NOT NULL,
    scan_type VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    results JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);
```

## Performance Optimization

### Backend Optimizations
1. **Connection Pooling**: PostgreSQL connection pooling with SQLAlchemy
2. **Caching**: Redis for API response caching
3. **Async Operations**: Full async/await implementation
4. **Background Tasks**: Celery for long-running scans
5. **Rate Limiting**: FastAPI-limiter for API rate limiting

### Frontend Optimizations
1. **Code Splitting**: Lazy loading of components
2. **State Management**: Zustand or Redux Toolkit
3. **API Client**: React Query for caching and synchronization
4. **Bundle Optimization**: Tree shaking and module federation

## Monitoring and Observability

### Logging Strategy
```python
import structlog
from fastapi import Request

# Structured logging
logger = structlog.get_logger()

@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    
    logger.info(
        "HTTP request processed",
        method=request.method,
        url=str(request.url),
        status_code=response.status_code,
        process_time=process_time
    )
    return response
```

### Health Checks
```python
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "services": {
            "database": await check_database_health(),
            "redis": await check_redis_health(),
            "security_tools": await check_security_tools_health()
        }
    }
```

## Testing Strategy

### Backend Testing
```python
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_security_dashboard_auth():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        # Test authentication required
        response = await ac.get("/api/v1/security/dashboard")
        assert response.status_code == 401
        
        # Test with valid token
        token = await get_test_token()
        headers = {"Authorization": f"Bearer {token}"}
        response = await ac.get("/api/v1/security/dashboard", headers=headers)
        assert response.status_code == 200
```

## Deployment Architecture

### Docker Configuration
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ips-security-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ips-security-backend
  template:
    metadata:
      labels:
        app: ips-security-backend
    spec:
      containers:
      - name: backend
        image: ips-security-backend:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: url
```

This architecture provides a solid foundation for a secure, scalable, and maintainable security management platform.