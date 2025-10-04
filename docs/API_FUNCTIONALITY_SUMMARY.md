# Frontend API Functionality Summary

This document provides a comprehensive overview of all API services and their functionality implemented in the frontend application.

## Table of Contents
1. [Agentic Penetration Testing API](#agentic-penetration-testing-api)
2. [IPSSTC Backend API](#ipsstc-backend-api)
3. [FastAPI Client](#fastapi-client)
4. [Security Services API](#security-services-api)
5. [Enhanced Security Service](#enhanced-security-service)
6. [OpenAI Service](#openai-service)
7. [Legacy Security API](#legacy-security-api)

---

## Agentic Penetration Testing API

**File**: `src/services/agenticPentestApi.ts`

### Overview
Orchestrates AI-driven penetration testing by integrating with Kali Linux security tools and providing real-time session updates via WebSockets.

### Key Features
- **WebSocket Integration**: Real-time session updates and tool output streaming
- **Session Management**: Create, start, stop, and monitor penetration testing sessions
- **LLM Configuration**: Support for multiple AI providers (OpenAI, Anthropic, Google, etc.)
- **Tool Orchestration**: Execute and monitor various Kali Linux tools

### Core Methods

#### Session Management
```typescript
createSession(config: SessionConfig): Promise<{ session_id: string }>
startSession(sessionId: string): Promise<void>
stopSession(sessionId: string): Promise<void>
getSessionStatus(sessionId: string): Promise<SessionStatus>
getActiveSessions(): Promise<SessionInfo[]>
```

#### Security Tool Execution
```typescript
runNmapScan(sessionId: string, config: NmapConfig): Promise<ScanResult>
runSQLMapScan(sessionId: string, config: SQLMapConfig): Promise<ScanResult>
runNiktoScan(sessionId: string, config: NiktoConfig): Promise<ScanResult>
runAmassEnum(sessionId: string, config: AmassConfig): Promise<ScanResult>
runSn1perScan(sessionId: string, config: Sn1perConfig): Promise<ScanResult>
```

#### AI Analysis
```typescript
analyzeNmapResults(sessionId: string, scanResults: any): Promise<AnalysisResult>
executeRecommendedStep(sessionId: string, stepId: string): Promise<ExecutionResult>
generateReport(sessionId: string, format: string): Promise<Report>
```

#### Configuration
```typescript
setLLMConfiguration(provider: string, apiKey: string, model?: string): Promise<void>
```

### WebSocket Events
- `session_update`: Real-time session status updates
- `tool_output`: Live tool execution output
- `analysis_complete`: AI analysis results
- `error`: Error notifications

---

## IPSSTC Backend API

**File**: `src/services/ipsstcApi.ts`

### Overview
Comprehensive API service for interacting with the IPSSTC backend, managing targets, scans, and security tools with WebSocket support for real-time updates.

### Key Features
- **Target Management**: CRUD operations for scan targets
- **GVM/OpenVAS Integration**: Vulnerability scanning with full scan lifecycle
- **ZAP Integration**: Web application security testing
- **Wazuh Integration**: SIEM log management
- **Recon-ng & SpiderFoot**: OSINT capabilities
- **AI Report Generation**: Automated security report creation

### Core Methods

#### Target Management
```typescript
getTargets(): Promise<TargetOut[]>
createOrUpdateTarget(target: TargetIn): Promise<TargetOut>
deleteTarget(targetId: string): Promise<void>
```

#### GVM/OpenVAS Operations
```typescript
getGvmStatus(): Promise<any>
getPortLists(): Promise<any[]>
getScanners(): Promise<ScannerOut[]>
getScanConfigs(): Promise<any[]>
createTask(task: TaskIn): Promise<any>
startScan(taskId: string): Promise<any>
getReports(): Promise<ReportOut[]>
downloadReport(reportId: string, format: string): Promise<Blob>
getSchedules(): Promise<any[]>
```

#### ZAP Proxy Operations
```typescript
startZapScan(scanRequest: ZapScanRequest): Promise<any>
getZapReports(): Promise<any[]>
downloadZapReport(reportId: string): Promise<Blob>
```

#### Wazuh Operations
```typescript
getWazuhLogs(request: WazuhLogRequest): Promise<any>
getWazuhStatus(): Promise<any>
downloadWazuhLog(logId: string): Promise<Blob>
```

#### OSINT Operations
```typescript
scheduleReconScan(scanRequest: ReconScanRequest): Promise<any>
launchSpiderfoot(scanRequest: SpiderScanRequest): Promise<any>
```

#### AI & Reporting
```typescript
chatbotHttp(request: ChatbotRequest): Promise<any>
generateReport(request: ReportRequest): Promise<ReportResponse>
```

#### Health Checks
```typescript
healthCheck(): Promise<any>
readinessCheck(): Promise<any>
livenessCheck(): Promise<any>
```

### WebSocket Integration
Maintains persistent WebSocket connection for real-time updates from backend services.

---

## FastAPI Client

**File**: `src/services/fastApiClient.ts`

### Overview
General-purpose FastAPI backend client with built-in retry logic, timeout handling, and comprehensive error management.

### Key Features
- **Automatic Retries**: Configurable retry attempts with exponential backoff
- **Timeout Management**: Request timeout protection
- **Comprehensive Logging**: Detailed request/response logging
- **Mock Data Support**: Development fallbacks

### Core Methods

#### Wazuh Operations
```typescript
getWazuhAgents(page?: number, limit?: number): Promise<WazuhAgent[]>
getWazuhAlerts(page?: number, limit?: number): Promise<WazuhAlert[]>
searchWazuhAlerts(query: string): Promise<WazuhAlert[]>
searchWazuhVulnerabilities(agentId: string): Promise<any[]>
restartWazuhAgent(agentId: string): Promise<void>
```

#### Health Monitoring
```typescript
getServicesHealth(): Promise<ServiceHealth[]>
checkServiceHealth(serviceName: string): Promise<ServiceHealth>
```

#### GVM Operations
```typescript
listGvmTargets(): Promise<any[]>
createGvmTarget(target: any): Promise<any>
deleteGvmTarget(targetId: string): Promise<void>
listGvmTasks(): Promise<any[]>
createGvmTask(task: any): Promise<any>
startGvmTask(taskId: string): Promise<any>
getGvmReport(reportId: string): Promise<any>
```

#### ZAP Operations
```typescript
getZapVersion(): Promise<any>
startZapScan(target: string): Promise<any>
```

#### SpiderFoot Operations
```typescript
getSpiderfootScans(): Promise<any[]>
startSpiderfootScan(target: string): Promise<any>
```

#### WebSocket
```typescript
connectWebSocket(): WebSocket | null
```

### Request Configuration
- **Base URL**: Configurable via environment
- **Timeout**: 30 seconds default
- **Retry Attempts**: 3 attempts with exponential backoff (2s, 4s, 8s)

---

## Security Services API

**File**: `src/services/securityServicesApi.ts`

### Overview
Robust API client for security tools with Kubernetes service discovery, API key management, comprehensive retry logic, and real-time alert streaming.

### Key Features
- **Service Discovery**: Automatic Kubernetes service endpoint resolution
- **API Key Authentication**: Secure API key management from environment
- **Circuit Breaker Pattern**: Resilient failure handling
- **WebSocket Streaming**: Real-time security alerts
- **Connectivity Testing**: Comprehensive service health validation

### Core Methods

#### Health Checks
```typescript
checkWazuhHealth(): Promise<ApiResponse<any>>
checkGvmHealth(): Promise<ApiResponse<any>>
checkZapHealth(): Promise<ApiResponse<any>>
checkSpiderfootHealth(): Promise<ApiResponse<any>>
```

#### Wazuh Operations
```typescript
getWazuhAgents(): Promise<ApiResponse<WazuhAgent[]>>
getWazuhAlerts(limit?: number): Promise<ApiResponse<WazuhAlert[]>>
restartWazuhAgent(agentId: string): Promise<ApiResponse<void>>
```

#### GVM Operations
```typescript
startGvmScan(targetId: string, configId: string): Promise<ApiResponse<string>>
getGvmScanResults(taskId: string): Promise<ApiResponse<any>>
listGvmTasks(): Promise<ApiResponse<any[]>>
```

#### ZAP Operations
```typescript
startZapScan(targetUrl: string): Promise<ApiResponse<string>>
getZapScanProgress(scanId: string): Promise<ApiResponse<number>>
getZapAlerts(baseUrl: string): Promise<ApiResponse<any[]>>
```

#### SpiderFoot Operations
```typescript
startSpiderfootScan(target: string): Promise<ApiResponse<string>>
getSpiderfootResults(scanId: string): Promise<ApiResponse<any[]>>
```

#### Service Management
```typescript
validateServiceConfig(config: ServiceConfig): { valid: boolean; errors: string[] }
runConnectivityTests(): Promise<Record<string, { success: boolean; responseTime: number; error?: string }>>
cleanup(): void
```

### WebSocket Events
Real-time alerts dispatched via custom events:
- `security:wazuh:alert`
- `security:gvm:update`
- `security:zap:finding`

### Retry Configuration
- **Max Retries**: 3 attempts
- **Backoff Strategy**: Exponential (1s, 2s, 4s)
- **Timeout**: 30 seconds per request

---

## Enhanced Security Service

**File**: `src/services/enhancedSecurityService.ts`

### Overview
Production-ready security service with advanced resilience patterns including circuit breaker, comprehensive health monitoring, and real-time WebSocket updates.

### Key Features
- **Circuit Breaker Pattern**: Automatic service failure isolation
- **Health Monitoring**: Continuous service health checks
- **WebSocket Management**: Reliable real-time data streaming with auto-reconnect
- **Scan Management**: Centralized scan lifecycle tracking
- **Toast Notifications**: User-friendly status updates

### Core Methods

#### Wazuh Operations
```typescript
getWazuhAgents(): Promise<WazuhAgent[]>
getWazuhAlerts(limit?: number): Promise<WazuhAlert[]>
restartWazuhAgent(agentId: string): Promise<void>
```

#### Health Monitoring
```typescript
getHealthStatuses(): SecurityServiceHealth[]
getServiceHealth(service: string): SecurityServiceHealth | undefined
```

#### Circuit Breaker
```typescript
// Automatic circuit breaker management
canExecute(service: string): boolean
recordSuccess(service: string): void
recordFailure(service: string): void
```

### Circuit Breaker Configuration
- **Max Failures**: 3 consecutive failures
- **Reset Timeout**: 60 seconds
- **States**: closed, open, half-open

### WebSocket Features
- **Auto-Reconnect**: Exponential backoff (2s, 4s, 8s, 16s, 32s)
- **Max Reconnect Attempts**: 5 attempts
- **Event Types**:
  - `wazuh_alert`: Security alerts
  - `service_health`: Health status updates
  - `scan_progress`: Scan progress updates
  - `scan_complete`: Scan completion notifications

### Health Check Interval
- **Frequency**: Every 30 seconds
- **Services Monitored**: Wazuh, GVM, ZAP, SpiderFoot

---

## OpenAI Service

**File**: `src/services/openaiService.ts`

### Overview
AI-powered report generation service using OpenAI's GPT models for creating tailored security reports, executive summaries, and research-enhanced content.

### Key Features
- **Report Generation**: Audience-specific security reports
- **Research Integration**: Enhance reports with latest security research
- **Executive Summaries**: High-level business-focused summaries
- **Flexible Configuration**: Customizable temperature, token limits, and model selection

### Core Methods

#### Chat Completions
```typescript
generateChatCompletion(request: OpenAIRequest): Promise<OpenAIResponse>
```

#### Report Generation
```typescript
generateSecurityReport(
  reportData: any,
  audienceType: string,
  templateName: string,
  customInstructions?: string
): Promise<string>
```

#### Report Enhancement
```typescript
enhanceWithResearch(content: string, researchData: string): Promise<string>
```

#### Executive Summaries
```typescript
generateExecutiveSummary(detailedReport: string): Promise<string>
```

### Configuration Options
- **Models**: GPT-4 (default), GPT-3.5-turbo
- **Temperature**: 0.2-0.7 (context-dependent)
- **Max Tokens**: 800-4000 based on output type
- **Top P**: Configurable (default: 1)
- **Frequency/Presence Penalty**: Configurable

### Report Types
1. **Executive Summary**: Concise, business-focused (2-3 paragraphs)
2. **Technical Report**: Detailed technical analysis with code examples
3. **Compliance Report**: Regulatory and standards-focused
4. **Risk Assessment**: Risk-prioritized findings
5. **Enhanced Research**: Latest security research integration

---

## Legacy Security API

**File**: `src/services/securityApi.ts`

### Overview
Legacy multi-service security API providing class-based interfaces for Wazuh, OpenVAS, ZAP, and SpiderFoot. Maintained for backward compatibility.

### Service Classes

#### WazuhService
```typescript
checkConnection(): Promise<ApiConnectionStatus>
getAgents(): Promise<any[]>
getAlerts(limit?: number): Promise<any[]>
getStatus(): ApiConnectionStatus
```

#### OpenVASService
```typescript
checkConnection(): Promise<ApiConnectionStatus>
startScan(targetId: string, configId: string): Promise<string>
getScanResults(taskId: string): Promise<any>
getStatus(): ApiConnectionStatus
```

#### ZAPService
```typescript
checkConnection(): Promise<ApiConnectionStatus>
startOWASPScan(targetUrl: string): Promise<string>
getScanProgress(scanId: string): Promise<number>
getStatus(): ApiConnectionStatus
```

#### SpiderfootService
```typescript
checkConnection(): Promise<ApiConnectionStatus>
startScan(target: string, modules?: string[]): Promise<string>
getScanResults(scanId: string): Promise<any[]>
getStatus(): ApiConnectionStatus
```

#### SecurityApiManager
```typescript
initializeServices(): void
checkAllConnections(): Promise<Map<string, ApiConnectionStatus>>
getService(serviceName: string): any
getAllStatuses(): Map<string, ApiConnectionStatus>
```

### Default Configurations
- **Wazuh**: `localhost:55000`
- **OpenVAS**: `localhost:9392`
- **ZAP**: `localhost:8080`
- **SpiderFoot**: `localhost:5001`

---

## Common Patterns & Best Practices

### Error Handling
All services implement comprehensive error handling:
- Try-catch blocks with detailed logging
- User-friendly error messages via toast notifications
- Graceful degradation with mock data fallbacks
- Proper error propagation to UI components

### WebSocket Management
Consistent WebSocket patterns across services:
- Automatic reconnection with exponential backoff
- Custom event dispatching for UI updates
- Connection status monitoring
- Cleanup on component unmount

### Retry Strategies
Multiple retry approaches implemented:
- **Exponential Backoff**: 2^n * 1000ms delay
- **Fixed Attempts**: Typically 3-5 retries
- **Circuit Breaker**: Prevent cascading failures
- **Timeout Protection**: 30-second default timeouts

### Authentication
Security across all services:
- API key authentication from environment variables
- Bearer token support
- Basic authentication for legacy systems
- Secure credential storage

### Type Safety
Full TypeScript implementation:
- Interface definitions for all requests/responses
- Generic type parameters for API responses
- Strict null checks
- Comprehensive type exports

---

## Environment Configuration

All services read from environment configuration:

```typescript
// Environment Variables
VITE_BACKEND_API_URL        // Backend API base URL
VITE_WEBSOCKET_URL          // WebSocket endpoint
VITE_WAZUH_API_KEY          // Wazuh authentication
VITE_ZAP_API_KEY            // ZAP authentication
VITE_SPIDERFOOT_API_KEY     // SpiderFoot authentication
VITE_OPENAI_API_KEY         // OpenAI authentication
```

---

## Integration Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     Frontend Application                     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐  ┌──────────────────┐                │
│  │ Components       │  │ React Hooks      │                │
│  │ - Dashboard      │  │ - useRealTime... │                │
│  │ - Management     │  │ - useSecurity... │                │
│  └────────┬─────────┘  └────────┬─────────┘                │
│           │                     │                            │
│           └─────────┬───────────┘                            │
│                     │                                        │
│           ┌─────────▼──────────────────┐                    │
│           │   Service Layer            │                    │
│           ├────────────────────────────┤                    │
│           │ - agenticPentestApi        │                    │
│           │ - ipsstcApi                │                    │
│           │ - fastApiClient            │                    │
│           │ - securityServicesApi      │                    │
│           │ - enhancedSecurityService  │                    │
│           │ - openaiService            │                    │
│           └─────────┬──────────────────┘                    │
│                     │                                        │
└─────────────────────┼────────────────────────────────────────┘
                      │
          ┌───────────┴───────────┐
          │                       │
    ┌─────▼──────┐         ┌─────▼──────┐
    │ HTTP/REST  │         │ WebSocket  │
    └─────┬──────┘         └─────┬──────┘
          │                       │
          └───────────┬───────────┘
                      │
┌─────────────────────▼────────────────────────────────────────┐
│                    Backend Services                          │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Wazuh   │  │   GVM    │  │   ZAP    │  │ AI LLMs  │   │
│  │   SIEM   │  │ OpenVAS  │  │  Proxy   │  │ Services │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │ Recon-ng │  │Kali Tools│  │ FastAPI  │                  │
│  └──────────┘  └──────────┘  └──────────┘                  │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

---

## Summary Statistics

### Total API Services: 7

### Total API Endpoints: ~150+

### Capabilities:
- ✅ Penetration Testing Automation
- ✅ Vulnerability Scanning (GVM/OpenVAS)
- ✅ Web Application Security Testing (ZAP)
- ✅ SIEM & Log Management (Wazuh)
- ✅ OSINT & Reconnaissance
- ✅ AI-Powered Report Generation
- ✅ Real-time Security Monitoring
- ✅ Health & Status Monitoring
- ✅ Multi-Provider LLM Integration

### Resilience Features:
- Circuit Breaker Pattern
- Exponential Backoff Retry
- Request Timeout Protection
- WebSocket Auto-Reconnection
- Graceful Degradation
- Mock Data Fallbacks

### Security Features:
- API Key Authentication
- Bearer Token Support
- Secure Credential Storage
- Environment Variable Configuration
- CORS Handling
- Request Validation

---

## Maintenance Notes

### Active Services
- ✅ **agenticPentestApi**: Actively maintained, latest implementation
- ✅ **ipsstcApi**: Actively maintained, full-featured
- ✅ **fastApiClient**: Actively maintained, production-ready
- ✅ **securityServicesApi**: Actively maintained, enterprise-grade
- ✅ **enhancedSecurityService**: Actively maintained, resilient patterns

### Legacy Services
- ⚠️ **securityApi.ts**: Legacy implementation, consider migrating to newer services
- ⚠️ Contains direct service integrations (should use backend proxy)

### Recommended Migration Path
1. Phase out direct service connections in `securityApi.ts`
2. Route all requests through backend APIs for security
3. Consolidate duplicate functionality
4. Standardize error handling and retry logic
5. Implement consistent WebSocket patterns

---

## Related Documentation
- [File Structure & Architecture](./FILE_STRUCTURE_AND_ARCHITECTURE.md)
- [Backend Developer Guide](./BACKEND_DEVELOPER_GUIDE.md)
- [API Specifications](./API_SPECIFICATIONS.md)
- [Third Party Integrations](./THIRD_PARTY_INTEGRATIONS.md)
