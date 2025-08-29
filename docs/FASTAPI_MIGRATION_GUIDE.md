# FastAPI Migration Guide

## Migration Overview

This guide provides a comprehensive roadmap for migrating the IPS Security Center from a frontend-only React application to a FastAPI backend with enhanced security, scalability, and maintainability.

## Prerequisites

### Required Tools
- Python 3.11+
- PostgreSQL 14+
- Redis 6+
- Docker & Docker Compose
- Node.js 18+ (for frontend development)

### Development Environment Setup
```bash
# Backend setup
cd backend/
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or venv\Scripts\activate  # Windows
pip install -r requirements.txt

# Database setup
docker-compose up -d postgres redis

# Run migrations
alembic upgrade head

# Start FastAPI server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Phase 1: Backend Foundation

### 1.1 Project Structure Setup

Create the following directory structure:

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py           # Configuration management
│   │   ├── database.py         # Database connection & session
│   │   ├── security.py         # Authentication & authorization
│   │   ├── logging.py          # Structured logging setup
│   │   └── exceptions.py       # Custom exception handlers
│   ├── api/
│   │   ├── __init__.py
│   │   ├── deps.py             # Common dependencies
│   │   └── v1/
│   │       ├── __init__.py
│   │       ├── auth.py         # Authentication endpoints
│   │       ├── security.py     # Security tool endpoints
│   │       ├── scans.py        # Scan management endpoints
│   │       ├── reports.py      # Report generation endpoints
│   │       └── websocket.py    # WebSocket endpoints
│   ├── services/
│   │   ├── __init__.py
│   │   ├── auth_service.py     # Authentication business logic
│   │   ├── security_integration.py # Security tools integration
│   │   ├── wazuh_service.py    # Wazuh SIEM integration
│   │   ├── gvm_service.py      # OpenVAS/GVM integration
│   │   ├── zap_service.py      # OWASP ZAP integration
│   │   ├── spiderfoot_service.py # SpiderFoot integration
│   │   └── notification_service.py # Real-time notifications
│   ├── models/
│   │   ├── __init__.py
│   │   ├── base.py             # Base model class
│   │   ├── user.py             # User models
│   │   ├── security_tool.py    # Security tool models
│   │   ├── scan.py             # Scan models
│   │   └── report.py           # Report models
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── base.py             # Base Pydantic schemas
│   │   ├── user.py             # User schemas
│   │   ├── security.py         # Security tool schemas
│   │   ├── scan.py             # Scan schemas
│   │   └── report.py           # Report schemas
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── security.py         # Security utilities
│   │   ├── validators.py       # Custom validators
│   │   └── helpers.py          # Helper functions
│   └── tests/
│       ├── __init__.py
│       ├── conftest.py         # Test configuration
│       ├── test_auth.py        # Authentication tests
│       ├── test_security.py    # Security integration tests
│       └── test_websocket.py   # WebSocket tests
├── alembic/                    # Database migrations
├── docker-compose.yml          # Development environment
├── Dockerfile                  # Production container
├── requirements.txt            # Python dependencies
├── requirements-dev.txt        # Development dependencies
└── pyproject.toml             # Project configuration
```

### 1.2 Core Configuration

**app/core/config.py**
```python
from pydantic_settings import BaseSettings
from typing import Optional, List
import secrets

class Settings(BaseSettings):
    # Application
    PROJECT_NAME: str = "IPS Security Center"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = secrets.token_urlsafe(32)
    
    # Security
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"
    
    # Database
    DATABASE_URL: str = "postgresql://user:password@localhost/ips_security"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000", "https://localhost:3000"]
    
    # Security Tools Configuration
    WAZUH_API_URL: Optional[str] = None
    WAZUH_API_KEY: Optional[str] = None
    
    GVM_API_URL: Optional[str] = None
    GVM_USERNAME: Optional[str] = None
    GVM_PASSWORD: Optional[str] = None
    
    ZAP_API_URL: Optional[str] = None
    ZAP_API_KEY: Optional[str] = None
    
    SPIDERFOOT_API_URL: Optional[str] = None
    SPIDERFOOT_API_KEY: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
```

**app/core/database.py**
```python
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    poolclass=StaticPool,
    pool_pre_ping=True,
    pool_recycle=300
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

### 1.3 Main Application Setup

**app/main.py**
```python
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import time
import structlog

from app.core.config import settings
from app.core.exceptions import CustomException
from app.api.v1 import auth, security, scans, reports, websocket

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Configure properly for production
)

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    
    logger.info(
        "HTTP request processed",
        method=request.method,
        url=str(request.url),
        status_code=response.status_code,
        process_time=round(process_time, 4)
    )
    return response

# Exception handlers
@app.exception_handler(CustomException)
async def custom_exception_handler(request: Request, exc: CustomException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "error_code": exc.error_code}
    )

# Include routers
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["authentication"])
app.include_router(security.router, prefix=f"{settings.API_V1_STR}/security", tags=["security"])
app.include_router(scans.router, prefix=f"{settings.API_V1_STR}/scans", tags=["scans"])
app.include_router(reports.router, prefix=f"{settings.API_V1_STR}/reports", tags=["reports"])
app.include_router(websocket.router, prefix=f"{settings.API_V1_STR}/ws", tags=["websocket"])

@app.get("/")
async def root():
    return {"message": "IPS Security Center API", "version": settings.VERSION}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": settings.VERSION
    }
```

## Phase 2: Authentication System

### 2.1 User Models

**app/models/user.py**
```python
from sqlalchemy import Column, String, Boolean, DateTime, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
import enum

from app.models.base import Base

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(SQLEnum(UserRole), default=UserRole.VIEWER)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
```

### 2.2 Authentication Service

**app/services/auth_service.py**
```python
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        return pwd_context.hash(password)
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str) -> Optional[str]:
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            email: str = payload.get("sub")
            if email is None:
                return None
            return email
        except JWTError:
            return None
    
    @staticmethod
    def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return None
        if not AuthService.verify_password(password, user.hashed_password):
            return None
        return user
    
    @staticmethod
    def create_user(db: Session, user_data: UserCreate) -> User:
        hashed_password = AuthService.get_password_hash(user_data.password)
        db_user = User(
            email=user_data.email,
            hashed_password=hashed_password,
            full_name=user_data.full_name,
            role=user_data.role
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
```

## Phase 3: Security Tools Integration

### 3.1 Security Service Base Class

**app/services/security_integration.py**
```python
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import httpx
import asyncio
from datetime import datetime, timedelta
import structlog

logger = structlog.get_logger()

class SecurityServiceBase(ABC):
    def __init__(self, base_url: str, api_key: Optional[str] = None, 
                 username: Optional[str] = None, password: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.username = username
        self.password = password
        self.client = httpx.AsyncClient(timeout=30.0)
        self._last_health_check = None
        self._is_healthy = False
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check if the service is healthy and responsive"""
        pass
    
    @abstractmethod
    async def get_status(self) -> Dict[str, Any]:
        """Get service status and statistics"""
        pass
    
    async def make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request with error handling and retries"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        # Add authentication headers
        headers = kwargs.get('headers', {})
        if self.api_key:
            headers['X-API-Key'] = self.api_key
        elif self.username and self.password:
            auth = httpx.BasicAuth(self.username, self.password)
            kwargs['auth'] = auth
        
        kwargs['headers'] = headers
        
        try:
            response = await self.client.request(method, url, **kwargs)
            response.raise_for_status()
            
            # Try to parse JSON, fallback to text
            try:
                return response.json()
            except:
                return {"data": response.text, "status_code": response.status_code}
                
        except httpx.HTTPError as e:
            logger.error(f"HTTP error in {self.__class__.__name__}", error=str(e), url=url)
            raise
        except Exception as e:
            logger.error(f"Unexpected error in {self.__class__.__name__}", error=str(e), url=url)
            raise
    
    async def cached_health_check(self, cache_duration: int = 300) -> Dict[str, Any]:
        """Health check with caching to avoid excessive requests"""
        now = datetime.utcnow()
        
        if (self._last_health_check and 
            (now - self._last_health_check) < timedelta(seconds=cache_duration)):
            return {"status": "healthy" if self._is_healthy else "unhealthy", "cached": True}
        
        try:
            result = await self.health_check()
            self._is_healthy = True
            self._last_health_check = now
            return result
        except Exception as e:
            self._is_healthy = False
            self._last_health_check = now
            logger.error(f"Health check failed for {self.__class__.__name__}", error=str(e))
            return {"status": "unhealthy", "error": str(e)}
```

### 3.2 Wazuh Service Implementation

**app/services/wazuh_service.py**
```python
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import structlog

from app.services.security_integration import SecurityServiceBase

logger = structlog.get_logger()

class WazuhService(SecurityServiceBase):
    def __init__(self, base_url: str, api_key: str):
        super().__init__(base_url, api_key=api_key)
        self.api_version = "v1"
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Wazuh API health"""
        try:
            result = await self.make_request("GET", f"/{self.api_version}/")
            return {
                "status": "healthy",
                "service": "wazuh",
                "version": result.get("data", {}).get("api_version"),
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "service": "wazuh",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def get_status(self) -> Dict[str, Any]:
        """Get Wazuh cluster status"""
        try:
            cluster_info = await self.make_request("GET", f"/{self.api_version}/cluster/status")
            manager_info = await self.make_request("GET", f"/{self.api_version}/manager/info")
            
            return {
                "cluster": cluster_info.get("data"),
                "manager": manager_info.get("data"),
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error("Failed to get Wazuh status", error=str(e))
            raise
    
    async def get_agents(self, limit: int = 100, offset: int = 0, 
                        status: Optional[str] = None) -> Dict[str, Any]:
        """Get Wazuh agents"""
        params = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
            
        try:
            result = await self.make_request("GET", f"/{self.api_version}/agents", params=params)
            return result
        except Exception as e:
            logger.error("Failed to get Wazuh agents", error=str(e))
            raise
    
    async def get_alerts(self, limit: int = 100, offset: int = 0,
                        severity: Optional[str] = None, agent_id: Optional[str] = None,
                        time_range: Optional[str] = None) -> Dict[str, Any]:
        """Get Wazuh alerts with filtering"""
        params = {"limit": limit, "offset": offset, "sort": "-timestamp"}
        
        if severity:
            params["rule.level"] = severity
        if agent_id:
            params["agent.id"] = agent_id
        if time_range:
            # Parse time range (e.g., "1d", "1h", "30m")
            params["timestamp"] = self._parse_time_range(time_range)
        
        try:
            result = await self.make_request("GET", f"/{self.api_version}/alerts", params=params)
            return result
        except Exception as e:
            logger.error("Failed to get Wazuh alerts", error=str(e))
            raise
    
    async def restart_agent(self, agent_id: str) -> Dict[str, Any]:
        """Restart a Wazuh agent"""
        try:
            result = await self.make_request("PUT", f"/{self.api_version}/agents/{agent_id}/restart")
            return result
        except Exception as e:
            logger.error(f"Failed to restart Wazuh agent {agent_id}", error=str(e))
            raise
    
    def _parse_time_range(self, time_range: str) -> str:
        """Parse time range string to Wazuh timestamp format"""
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
            start_time = now - timedelta(hours=24)  # Default to 24 hours
        
        return f">={start_time.isoformat()}Z"
```

## Phase 4: API Endpoints

### 4.1 Security Endpoints

**app/api/v1/security.py**
```python
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any

from app.core.database import get_db
from app.core.security import get_current_active_user
from app.models.user import User
from app.services.wazuh_service import WazuhService
from app.services.gvm_service import GVMService
from app.services.zap_service import ZAPService
from app.services.spiderfoot_service import SpiderFootService
from app.core.config import settings

router = APIRouter()

# Initialize services
wazuh_service = WazuhService(settings.WAZUH_API_URL, settings.WAZUH_API_KEY)
gvm_service = GVMService(settings.GVM_API_URL, settings.GVM_USERNAME, settings.GVM_PASSWORD)
zap_service = ZAPService(settings.ZAP_API_URL, settings.ZAP_API_KEY)
spiderfoot_service = SpiderFootService(settings.SPIDERFOOT_API_URL, settings.SPIDERFOOT_API_KEY)

@router.get("/health")
async def check_all_services_health(
    current_user: User = Depends(get_current_active_user)
) -> Dict[str, Any]:
    """Check health of all security services"""
    health_checks = await asyncio.gather(
        wazuh_service.cached_health_check(),
        gvm_service.cached_health_check(),
        zap_service.cached_health_check(),
        spiderfoot_service.cached_health_check(),
        return_exceptions=True
    )
    
    return {
        "overall_status": "healthy" if all(
            isinstance(check, dict) and check.get("status") == "healthy" 
            for check in health_checks
        ) else "degraded",
        "services": {
            "wazuh": health_checks[0],
            "gvm": health_checks[1],
            "zap": health_checks[2],
            "spiderfoot": health_checks[3]
        }
    }

@router.get("/wazuh/agents")
async def get_wazuh_agents(
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None),
    current_user: User = Depends(get_current_active_user)
):
    """Get Wazuh agents"""
    try:
        async with wazuh_service:
            result = await wazuh_service.get_agents(limit=limit, offset=offset, status=status)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get Wazuh agents: {str(e)}")

@router.get("/wazuh/alerts")
async def get_wazuh_alerts(
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
    agent_id: Optional[str] = Query(None),
    time_range: Optional[str] = Query("24h"),
    current_user: User = Depends(get_current_active_user)
):
    """Get Wazuh alerts with filtering"""
    try:
        async with wazuh_service:
            result = await wazuh_service.get_alerts(
                limit=limit, offset=offset, severity=severity,
                agent_id=agent_id, time_range=time_range
            )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get Wazuh alerts: {str(e)}")

@router.put("/wazuh/agents/{agent_id}/restart")
async def restart_wazuh_agent(
    agent_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Restart a Wazuh agent"""
    if current_user.role not in ["admin", "analyst"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    try:
        async with wazuh_service:
            result = await wazuh_service.restart_agent(agent_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to restart agent: {str(e)}")
```

## Phase 5: WebSocket Implementation

### 5.1 WebSocket Manager

**app/api/v1/websocket.py**
```python
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException
from typing import List, Dict, Any
import json
import asyncio
import structlog
from datetime import datetime

from app.core.security import verify_websocket_token
from app.models.user import User

logger = structlog.get_logger()
router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.user_connections: Dict[str, List[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        self.active_connections.append(websocket)
        
        if user_id not in self.user_connections:
            self.user_connections[user_id] = []
        self.user_connections[user_id].append(websocket)
        
        logger.info("WebSocket connected", user_id=user_id, total_connections=len(self.active_connections))
    
    def disconnect(self, websocket: WebSocket, user_id: str):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        
        if user_id in self.user_connections:
            if websocket in self.user_connections[user_id]:
                self.user_connections[user_id].remove(websocket)
            if not self.user_connections[user_id]:
                del self.user_connections[user_id]
        
        logger.info("WebSocket disconnected", user_id=user_id, total_connections=len(self.active_connections))
    
    async def send_personal_message(self, message: Dict[str, Any], user_id: str):
        """Send message to specific user"""
        if user_id in self.user_connections:
            disconnected = []
            for connection in self.user_connections[user_id]:
                try:
                    await connection.send_text(json.dumps(message))
                except:
                    disconnected.append(connection)
            
            # Clean up disconnected connections
            for conn in disconnected:
                self.disconnect(conn, user_id)
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except:
                disconnected.append(connection)
        
        # Clean up disconnected connections
        for conn in disconnected:
            if conn in self.active_connections:
                self.active_connections.remove(conn)

manager = ConnectionManager()

@router.websocket("/security-alerts")
async def websocket_security_alerts(websocket: WebSocket, token: str):
    """WebSocket endpoint for real-time security alerts"""
    # Verify token
    user = await verify_websocket_token(token)
    if not user:
        await websocket.close(code=4001, reason="Unauthorized")
        return
    
    await manager.connect(websocket, str(user.id))
    
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Handle different message types
            if message.get("type") == "ping":
                await websocket.send_text(json.dumps({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat()
                }))
            elif message.get("type") == "subscribe":
                # Handle subscription to specific alert types
                await websocket.send_text(json.dumps({
                    "type": "subscribed",
                    "channels": message.get("channels", []),
                    "timestamp": datetime.utcnow().isoformat()
                }))
    
    except WebSocketDisconnect:
        manager.disconnect(websocket, str(user.id))
    except Exception as e:
        logger.error("WebSocket error", error=str(e), user_id=str(user.id))
        manager.disconnect(websocket, str(user.id))

# Background task to send real-time alerts
async def alert_broadcaster():
    """Background task to broadcast security alerts"""
    while True:
        try:
            # Simulate getting alerts from security services
            # In production, this would integrate with your security services
            await asyncio.sleep(10)  # Check every 10 seconds
            
            # Example alert
            alert = {
                "type": "security_alert",
                "source": "wazuh",
                "severity": "high",
                "message": "Suspicious login detected",
                "timestamp": datetime.utcnow().isoformat(),
                "details": {
                    "agent_id": "001",
                    "source_ip": "192.168.1.100",
                    "rule_id": "5710"
                }
            }
            
            await manager.broadcast(alert)
        
        except Exception as e:
            logger.error("Error in alert broadcaster", error=str(e))
            await asyncio.sleep(5)

# Start background task when module is imported
asyncio.create_task(alert_broadcaster())
```

This comprehensive migration guide provides the foundation for transforming your security platform into a robust, scalable FastAPI backend with proper authentication, security, and real-time capabilities.