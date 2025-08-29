# Developer Setup Guide - IPS Security Center

## Overview

This guide provides comprehensive instructions for setting up a development environment for the IPS Security Center, including both the current React frontend and the new FastAPI backend infrastructure.

## Prerequisites

### Required Software

#### Core Development Tools
- **Python 3.11+**: Backend development
- **Node.js 18+**: Frontend development and tooling
- **Git**: Version control
- **Docker & Docker Compose**: Container orchestration
- **PostgreSQL 14+**: Primary database
- **Redis 6+**: Caching and real-time features

#### Recommended IDEs
- **Visual Studio Code** with extensions:
  - Python
  - TypeScript and JavaScript
  - Docker
  - PostgreSQL
  - GitLens
  - REST Client
- **PyCharm Professional** (alternative for Python development)
- **WebStorm** (alternative for frontend development)

#### Development Tools
```bash
# Package managers
npm install -g yarn pnpm  # Frontend package managers
pip install poetry        # Python package manager

# Development utilities
npm install -g @types/node typescript tsx  # TypeScript tools
pip install black flake8 mypy bandit       # Python code quality tools

# Database tools
pip install pgcli        # PostgreSQL CLI
npm install -g redis-cli # Redis CLI (if not using Docker)
```

## Environment Setup

### 1. Repository Setup

```bash
# Clone the repository
git clone https://github.com/your-org/ips-security-center.git
cd ips-security-center

# Create development branch
git checkout -b feature/backend-migration
```

### 2. Backend Development Environment

#### Python Virtual Environment
```bash
# Create and activate virtual environment
cd backend/
python -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements-dev.txt
```

#### Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit environment variables
# Use your preferred editor to configure .env
```

**.env file template:**
```env
# Application Configuration
PROJECT_NAME=IPS Security Center
VERSION=1.0.0
ENVIRONMENT=development
DEBUG=true
SECRET_KEY=your-super-secret-key-change-in-production

# Database Configuration
DATABASE_URL=postgresql://ips_user:ips_password@localhost:5432/ips_security_dev
REDIS_URL=redis://localhost:6379/0

# CORS Configuration
BACKEND_CORS_ORIGINS=["http://localhost:3000","https://localhost:3000","http://localhost:5173","https://localhost:5173"]

# Security Tools Configuration (Development)
WAZUH_API_URL=http://localhost:55000
WAZUH_API_KEY=your-wazuh-development-key

GVM_API_URL=http://localhost:9390
GVM_USERNAME=admin
GVM_PASSWORD=admin

ZAP_API_URL=http://localhost:8080
ZAP_API_KEY=your-zap-development-key

SPIDERFOOT_API_URL=http://localhost:5001
SPIDERFOOT_API_KEY=your-spiderfoot-development-key

# JWT Configuration
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
ALGORITHM=HS256

# Logging Configuration
LOG_LEVEL=DEBUG
LOG_FORMAT=json

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=100

# Feature Flags
ENABLE_WEBSOCKETS=true
ENABLE_BACKGROUND_TASKS=true
ENABLE_METRICS=true
```

#### Database Setup
```bash
# Start database services
docker-compose up -d postgres redis

# Wait for services to be ready
sleep 10

# Run database migrations
alembic upgrade head

# Seed development data
python scripts/seed_dev_data.py
```

#### Database Migration Setup
```bash
# Initialize Alembic (only needed once)
alembic init alembic

# Create new migration
alembic revision --autogenerate -m "Create initial tables"

# Apply migrations
alembic upgrade head

# Downgrade if needed
alembic downgrade -1
```

### 3. Frontend Development Environment

```bash
# Navigate to frontend directory
cd ../frontend/  # or stay in root if frontend is in src/

# Install dependencies
npm install
# or
yarn install

# Create environment file
cp .env.example .env.local
```

**.env.local template:**
```env
# Development API Configuration
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_BASE_URL=ws://localhost:8000

# Feature Flags
VITE_ENABLE_DEV_TOOLS=true
VITE_ENABLE_DEBUG_LOGS=true

# Third-party integrations (if direct access needed for development)
VITE_ENABLE_MOCK_DATA=true
```

### 4. Security Tools Development Setup

#### Docker Compose for Security Services
Create `docker-compose.security.yml`:

```yaml
version: '3.8'

services:
  # Wazuh Manager (Development)
  wazuh-manager:
    image: wazuh/wazuh-manager:4.5.0
    container_name: wazuh-manager-dev
    restart: unless-stopped
    ports:
      - "1514:1514"
      - "1515:1515"
      - "514:514/udp"
      - "55000:55000"
    environment:
      - WAZUH_MANAGER_ADMIN_USER=admin
      - WAZUH_MANAGER_ADMIN_PASSWORD=SecretPassword
    volumes:
      - wazuh_api_configuration:/var/ossec/api/configuration
      - wazuh_etc:/var/ossec/etc
      - wazuh_logs:/var/ossec/logs
      - wazuh_queue:/var/ossec/queue
      - wazuh_var_multigroups:/var/ossec/var/multigroups
      - wazuh_integrations:/var/ossec/integrations
      - wazuh_active_response:/var/ossec/active-response/bin
      - wazuh_agentless:/var/ossec/agentless
      - wazuh_wodles:/var/ossec/wodles
      - filebeat_etc:/etc/filebeat
      - filebeat_var:/var/lib/filebeat

  # OpenVAS/GVM (Development)
  gvm:
    image: immauss/openvas:latest
    container_name: gvm-dev
    restart: unless-stopped
    ports:
      - "9392:9392"
      - "9390:9390"
    environment:
      - RELAYHOST=localhost
      - SMTPPORT=25
      - AUTO_SYNC=true
    volumes:
      - gvm_data:/data

  # OWASP ZAP (Development)
  zap:
    image: owasp/zap2docker-stable:latest
    container_name: zap-dev
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "8090:8090"
    command: zap-webswing.sh
    environment:
      - ZAP_AUTH=false
      - ZAP_WEBSWING=true

  # SpiderFoot (Development)
  spiderfoot:
    image: spiderfoot/spiderfoot:latest
    container_name: spiderfoot-dev
    restart: unless-stopped
    ports:
      - "5001:5001"
    volumes:
      - spiderfoot_data:/var/lib/spiderfoot

volumes:
  wazuh_api_configuration:
  wazuh_etc:
  wazuh_logs:
  wazuh_queue:
  wazuh_var_multigroups:
  wazuh_integrations:
  wazuh_active_response:
  wazuh_agentless:
  wazuh_wodles:
  filebeat_etc:
  filebeat_var:
  gvm_data:
  spiderfoot_data:

networks:
  default:
    name: ips-security-network
```

#### Start Security Services
```bash
# Start all security tools
docker-compose -f docker-compose.security.yml up -d

# Check service status
docker-compose -f docker-compose.security.yml ps

# View logs
docker-compose -f docker-compose.security.yml logs -f wazuh-manager
```

## Development Workflow

### 1. Daily Development Routine

#### Backend Development
```bash
# Activate virtual environment
source backend/venv/bin/activate

# Start database services
docker-compose up -d postgres redis

# Start FastAPI development server
cd backend/
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# In another terminal, start Celery worker (for background tasks)
celery -A app.worker worker --loglevel=info

# Start Celery beat (for scheduled tasks)
celery -A app.worker beat --loglevel=info
```

#### Frontend Development
```bash
# Start React development server
cd frontend/  # or root directory
npm run dev
# or
yarn dev

# Start Storybook (for component development)
npm run storybook
```

### 2. Code Quality Tools

#### Backend Code Quality
```bash
# Code formatting
black app/ tests/
isort app/ tests/

# Linting
flake8 app/ tests/
pylint app/

# Type checking
mypy app/

# Security scanning
bandit -r app/

# Run all quality checks
make quality-check
```

#### Frontend Code Quality
```bash
# Linting
npm run lint
npm run lint:fix

# Type checking
npm run type-check

# Testing
npm run test
npm run test:coverage

# Build check
npm run build
```

### 3. Testing Strategy

#### Backend Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
pytest tests/security/

# Run tests with specific markers
pytest -m "not slow"
pytest -m integration
```

#### Frontend Testing
```bash
# Unit tests
npm run test:unit

# Integration tests
npm run test:integration

# E2E tests
npm run test:e2e

# Visual regression tests
npm run test:visual

# Run all tests
npm run test:all
```

### 4. Database Development

#### Working with Migrations
```bash
# Create new migration
alembic revision --autogenerate -m "Add user roles table"

# Review generated migration
# Edit alembic/versions/[timestamp]_add_user_roles_table.py if needed

# Apply migration
alembic upgrade head

# Rollback migration
alembic downgrade -1

# Check current version
alembic current

# Show migration history
alembic history
```

#### Database Management
```bash
# Connect to database
pgcli postgresql://ips_user:ips_password@localhost:5432/ips_security_dev

# Backup database
pg_dump -h localhost -U ips_user -d ips_security_dev > backup.sql

# Restore database
psql -h localhost -U ips_user -d ips_security_dev < backup.sql

# Reset database (development only)
python scripts/reset_database.py
```

## Debugging Guide

### 1. Backend Debugging

#### FastAPI Debug Configuration
```python
# app/main.py - Development configuration
import debugpy

if settings.DEBUG:
    # Enable remote debugging
    debugpy.listen(("0.0.0.0", 5678))
    print("Waiting for debugger attach...")
    # debugpy.wait_for_client()  # Uncomment to wait for debugger
```

#### VS Code Debug Configuration
```json
// .vscode/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "FastAPI Debug",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/backend/venv/bin/uvicorn",
            "args": ["app.main:app", "--reload", "--host", "0.0.0.0", "--port", "8000"],
            "cwd": "${workspaceFolder}/backend",
            "env": {
                "PYTHONPATH": "${workspaceFolder}/backend"
            },
            "console": "integratedTerminal"
        },
        {
            "name": "Attach to FastAPI",
            "type": "python",
            "request": "attach",
            "connect": {
                "host": "localhost",
                "port": 5678
            },
            "pathMappings": [
                {
                    "localRoot": "${workspaceFolder}/backend",
                    "remoteRoot": "/app"
                }
            ]
        }
    ]
}
```

#### Common Debugging Commands
```bash
# View application logs
tail -f logs/app.log

# Monitor database queries
export DATABASE_URL="postgresql://ips_user:ips_password@localhost:5432/ips_security_dev?echo=true"

# Debug with pdb
import pdb; pdb.set_trace()

# Debug with ipdb (better interface)
import ipdb; ipdb.set_trace()
```

### 2. Frontend Debugging

#### React DevTools Setup
```bash
# Install React DevTools browser extension
# Available for Chrome, Firefox, and Edge

# Install Redux DevTools (if using Redux)
# Browser extension for state debugging
```

#### Debug Configuration
```typescript
// vite.config.ts - Development configuration
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    open: true,
    cors: true
  },
  define: {
    __DEV__: JSON.stringify(true)
  }
})
```

### 3. Integration Debugging

#### API Testing with HTTPie
```bash
# Install HTTPie
pip install httpie

# Test authentication
http POST localhost:8000/api/v1/auth/login email=admin@example.com password=admin123

# Test protected endpoint
http GET localhost:8000/api/v1/security/health "Authorization:Bearer <token>"

# Test WebSocket connection
wscat -c ws://localhost:8000/api/v1/ws/security-alerts?token=<token>
```

#### Docker Service Debugging
```bash
# Check container status
docker-compose ps

# View container logs
docker-compose logs -f wazuh-manager

# Execute commands in container
docker-compose exec wazuh-manager bash

# Inspect container
docker inspect wazuh-manager-dev
```

## Performance Optimization

### 1. Backend Performance

#### Database Optimization
```python
# Use connection pooling
from sqlalchemy.pool import QueuePool

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=20,
    max_overflow=30,
    pool_pre_ping=True,
    pool_recycle=3600
)
```

#### Async Best Practices
```python
# Use async/await properly
async def get_security_data():
    # Gather multiple async operations
    wazuh_data, gvm_data = await asyncio.gather(
        get_wazuh_alerts(),
        get_gvm_scans()
    )
    return {"wazuh": wazuh_data, "gvm": gvm_data}

# Use connection pooling for HTTP clients
connector = aiohttp.TCPConnector(limit=100, limit_per_host=10)
session = aiohttp.ClientSession(connector=connector)
```

#### Caching Strategy
```python
# Redis caching
from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend

@app.on_event("startup")
async def startup():
    redis = aioredis.from_url("redis://localhost", encoding="utf8")
    FastAPICache.init(RedisBackend(redis), prefix="ips-cache")

# Use caching decorator
@cache(expire=300)
async def get_cached_alerts():
    return await fetch_alerts_from_wazuh()
```

### 2. Frontend Performance

#### Bundle Optimization
```typescript
// vite.config.ts - Production optimization
export default defineConfig({
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          router: ['react-router-dom'],
          ui: ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu'],
        }
      }
    },
    chunkSizeWarningLimit: 1000
  }
})
```

#### React Performance
```typescript
// Use React.memo for expensive components
const SecurityDashboard = React.memo(({ data }) => {
  return <div>{/* Complex dashboard rendering */}</div>
})

// Use useMemo for expensive calculations
const processedAlerts = useMemo(() => {
  return alerts.filter(alert => alert.severity === 'high')
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
}, [alerts])

// Lazy load components
const AgenticPentestInterface = lazy(() => import('./AgenticPentestInterface'))
```

## Deployment Preparation

### 1. Environment Configuration

#### Production Environment Variables
```env
# Production .env template
PROJECT_NAME=IPS Security Center
VERSION=1.0.0
ENVIRONMENT=production
DEBUG=false
SECRET_KEY=super-secure-production-key

# Database (use connection pooling)
DATABASE_URL=postgresql://prod_user:secure_password@db.internal:5432/ips_security
REDIS_URL=redis://redis.internal:6379/0

# Security
ALLOWED_HOSTS=["ips-security.company.com"]
CORS_ORIGINS=["https://ips-security.company.com"]

# SSL/TLS
SSL_CERT_PATH=/etc/ssl/certs/ips-security.crt
SSL_KEY_PATH=/etc/ssl/private/ips-security.key

# Monitoring
SENTRY_DSN=https://your-sentry-dsn
DATADOG_API_KEY=your-datadog-key
```

### 2. Docker Production Images

#### Backend Dockerfile
```dockerfile
# Dockerfile.prod
FROM python:3.11-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

WORKDIR /app

# Copy dependencies from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash app
USER app

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

#### Frontend Dockerfile
```dockerfile
# Frontend Dockerfile.prod
FROM node:18-alpine as builder

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build application
RUN npm run build

# Production stage with nginx
FROM nginx:alpine

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

### 3. CI/CD Pipeline

#### GitHub Actions Workflow
```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test-backend:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        cd backend
        pip install -r requirements-dev.txt
    
    - name: Run tests
      run: |
        cd backend
        pytest --cov=app --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3

  test-frontend:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run tests
      run: npm run test:coverage
    
    - name: Build
      run: npm run build

  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run Bandit Security Scan
      run: |
        pip install bandit
        bandit -r backend/app -f json -o bandit-report.json
    
    - name: Run npm audit
      run: npm audit --audit-level moderate
```

This comprehensive developer setup guide provides everything needed to establish a productive development environment for the IPS Security Center project.