# Frontend Documentation - IPS Security Center

## Table of Contents
1. [Project Overview](#project-overview)
2. [File Structure](#file-structure)
3. [Core Architecture](#core-architecture)
4. [Component Documentation](#component-documentation)
5. [Service Layer](#service-layer)
6. [Hooks & State Management](#hooks--state-management)
7. [Type Definitions](#type-definitions)
8. [Integration Patterns](#integration-patterns)
9. [Routing & Navigation](#routing--navigation)
10. [Best Practices](#best-practices)

---

## Project Overview

**IPS Security Center** is a comprehensive cybersecurity management dashboard built with:
- **React 18** with TypeScript for type safety
- **Vite** for fast development and optimized builds
- **Tailwind CSS** for responsive, utility-first styling
- **shadcn/ui** for accessible, customizable UI components
- **TanStack Query** for efficient data fetching and caching
- **React Router** for client-side routing
- **Lovable Cloud (Supabase)** for backend integration

### Key Features
- Real-time security monitoring
- GVM (Greenbone Vulnerability Manager) integration
- AI-powered penetration testing interface
- Intelligent reporting system with RAG capabilities
- Documentation library with HackTricks integration
- System status monitoring

---

## File Structure

```
src/
├── assets/                      # Static assets (images, icons)
│   └── security-hero.jpg        # Hero image for landing page
├── components/                  # React components
│   ├── ui/                      # shadcn/ui base components
│   │   ├── button.tsx           # Button component with variants
│   │   ├── card.tsx             # Card container component
│   │   ├── dialog.tsx           # Modal dialog component
│   │   ├── input.tsx            # Text input component
│   │   ├── tabs.tsx             # Tab navigation component
│   │   ├── toast.tsx            # Toast notification component
│   │   └── ...                  # Other UI primitives
│   ├── ConnectionStatusIndicator.tsx    # API connection status badge
│   ├── DocumentationLibrary.tsx         # HackTricks documentation viewer
│   ├── EnhancedAgenticPentestInterface.tsx  # AI pentest interface
│   ├── EnvironmentConfigStatus.tsx      # Service configuration display
│   ├── GVMManagement.tsx                # GVM vulnerability scanner
│   ├── IntelligentReportingSystem.tsx   # RAG-based report generator
│   ├── IppsYChatPane.tsx                # AI chat assistant
│   ├── SecurityAssessmentReport.tsx     # Security report viewer
│   └── SecurityDashboard.tsx            # Main dashboard component
├── config/                      # Configuration files
│   └── environment.ts           # Environment & service configuration
├── hooks/                       # Custom React hooks
│   ├── use-mobile.tsx           # Mobile breakpoint detection
│   ├── use-toast.ts             # Toast notification hook
│   ├── useRealTimeSecurityData.ts   # Real-time security data hook
│   └── useSecurityStatus.ts         # Security status monitoring hook
├── integrations/                # External service integrations
│   └── supabase/
│       ├── client.ts            # Supabase client instance (auto-generated)
│       └── types.ts             # Supabase type definitions (auto-generated)
├── lib/                         # Utility functions
│   ├── gvmTransformers.ts       # GVM data transformation utilities
│   └── utils.ts                 # General utility functions (cn, etc.)
├── pages/                       # Route page components
│   ├── Index.tsx                # Landing/dashboard page
│   ├── GVMManagement.tsx        # GVM management page
│   ├── SystemStatus.tsx         # System status monitoring page
│   └── NotFound.tsx             # 404 error page
├── services/                    # API service layer
│   ├── agenticPentestApi.ts     # Agentic pentest API client
│   ├── enhancedSecurityService.ts   # Enhanced security service
│   ├── fastApiClient.ts         # FastAPI backend client
│   ├── ipsstcApi.ts             # IPSSTC API client
│   ├── openaiService.ts         # OpenAI/AI service integration
│   ├── securityApi.ts           # Security API client
│   └── securityServicesApi.ts   # Security services API
├── types/                       # TypeScript type definitions
│   ├── agenticPentest.ts        # Agentic pentest types
│   ├── reporting.ts             # Reporting system types
│   └── security.ts              # Security-related types
├── App.tsx                      # Root application component
├── index.css                    # Global styles & design tokens
├── main.tsx                     # Application entry point
└── vite-env.d.ts               # Vite environment type definitions
```

---

## Core Architecture

### Component Hierarchy

```
App (QueryClientProvider, Router)
├── TooltipProvider
├── Toaster (UI notifications)
├── Sonner (Toast notifications)
└── Routes
    ├── Index (Dashboard)
    │   ├── SecurityDashboard
    │   │   ├── SecurityAssessmentReport
    │   │   ├── IppsYChatPane
    │   │   └── ConnectionStatusIndicator
    │   ├── EnhancedAgenticPentestInterface
    │   ├── IntelligentReportingSystem
    │   └── DocumentationLibrary
    ├── GVMManagement
    │   ├── GVMManagement (component)
    │   └── ConnectionStatusIndicator
    ├── SystemStatus
    │   └── EnvironmentConfigStatus
    └── NotFound
```

### Design System

The application uses a **semantic token system** defined in `src/index.css`:

```css
:root {
  --background: 0 0% 100%;           /* Main background */
  --foreground: 222.2 84% 4.9%;      /* Text color */
  --primary: 221.2 83.2% 53.3%;      /* Primary brand color */
  --secondary: 210 40% 96.1%;        /* Secondary elements */
  --accent: 210 40% 96.1%;           /* Accent highlights */
  --destructive: 0 84.2% 60.2%;      /* Error/destructive actions */
  /* ... more tokens */
}
```

**Always use semantic tokens** instead of direct colors:
```tsx
// ✅ CORRECT
<div className="bg-background text-foreground border-border">

// ❌ WRONG
<div className="bg-white text-black border-gray-300">
```

---

## Component Documentation

### 1. SecurityDashboard
**Location:** `src/components/SecurityDashboard.tsx`

**Purpose:** Main dashboard component displaying security overview, metrics, and system status.

**Features:**
- Real-time security metrics display
- Integration with multiple security services
- Connection status monitoring
- Responsive grid layout

**Key Props:**
```typescript
interface SecurityDashboardProps {
  // No props - uses internal hooks for data
}
```

**Usage Example:**
```tsx
import { SecurityDashboard } from '@/components/SecurityDashboard';

function DashboardPage() {
  return (
    <div className="container mx-auto p-6">
      <SecurityDashboard />
    </div>
  );
}
```

**Internal Hooks:**
- `useSecurityStatus()` - Monitors security service health
- `useRealTimeSecurityData()` - Fetches real-time security metrics

---

### 2. EnhancedAgenticPentestInterface
**Location:** `src/components/EnhancedAgenticPentestInterface.tsx`

**Purpose:** AI-powered penetration testing interface with multiple attack modes, automation capabilities, and real-time feedback.

**Features:**
- Multiple scan modes (Quick, Standard, Deep, Custom)
- Tool selection (Nmap, Metasploit, Nikto, SQLMap, Burp Suite)
- Attack plan generation and execution
- Real-time scan progress tracking
- Vulnerability assessment with CVSS scoring

**Key Types:**
```typescript
interface ScanMode {
  id: string;
  name: string;
  description: string;
  icon: LucideIcon;
  estimatedTime: string;
}

interface AttackTool {
  id: string;
  name: string;
  description: string;
  icon: LucideIcon;
  category: 'reconnaissance' | 'exploitation' | 'post-exploitation';
}
```

**Usage Example:**
```tsx
import { EnhancedAgenticPentestInterface } from '@/components/EnhancedAgenticPentestInterface';

function PentestPage() {
  return (
    <div className="container mx-auto p-6">
      <h1 className="text-3xl font-bold mb-6">AI Penetration Testing</h1>
      <EnhancedAgenticPentestInterface />
    </div>
  );
}
```

**State Management:**
```typescript
const [selectedMode, setSelectedMode] = useState<string>('standard');
const [selectedTools, setSelectedTools] = useState<string[]>([]);
const [targetIp, setTargetIp] = useState<string>('');
const [scanProgress, setScanProgress] = useState<number>(0);
const [isScanning, setIsScanning] = useState<boolean>(false);
```

---

### 3. IntelligentReportingSystem
**Location:** `src/components/IntelligentReportingSystem.tsx`

**Purpose:** RAG (Retrieval-Augmented Generation) based reporting system for generating security assessment reports.

**Features:**
- AI-powered report generation
- Template selection (Executive Summary, Technical Deep-Dive, Compliance)
- Real-time report preview
- Export to PDF/DOCX
- Integration with HackTricks knowledge base

**Key Types:**
```typescript
interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  sections: string[];
}

interface GeneratedReport {
  id: string;
  title: string;
  content: string;
  template: string;
  generatedAt: string;
  findings: Finding[];
}
```

**Usage Example:**
```tsx
import { IntelligentReportingSystem } from '@/components/IntelligentReportingSystem';

function ReportsPage() {
  return (
    <div className="container mx-auto p-6">
      <IntelligentReportingSystem />
    </div>
  );
}
```

**API Integration:**
```typescript
// Fetches report data from backend
const generateReport = async (template: string, findings: Finding[]) => {
  const response = await fetch('/api/reports/generate', {
    method: 'POST',
    body: JSON.stringify({ template, findings }),
  });
  return response.json();
};
```

---

### 4. DocumentationLibrary
**Location:** `src/components/DocumentationLibrary.tsx`

**Purpose:** Searchable documentation library integrated with HackTricks cybersecurity knowledge base.

**Features:**
- Full-text search across documentation
- Category filtering (Web Exploitation, Network, Privilege Escalation, etc.)
- Markdown rendering
- Code syntax highlighting
- Bookmarking system

**Key Props:**
```typescript
interface DocumentationLibraryProps {
  initialSearchTerm?: string;
  onDocumentSelect?: (documentId: string) => void;
}
```

**Usage Example:**
```tsx
import { DocumentationLibrary } from '@/components/DocumentationLibrary';

function DocsPage() {
  const handleDocSelect = (docId: string) => {
    console.log('Selected document:', docId);
  };

  return (
    <DocumentationLibrary 
      initialSearchTerm="sql injection"
      onDocumentSelect={handleDocSelect}
    />
  );
}
```

**Backend Integration:**
```typescript
// Uses Supabase Edge Function for semantic search
const searchDocs = async (query: string) => {
  const { data, error } = await supabase.functions.invoke('search-hacktricks', {
    body: { query }
  });
  return data;
};
```

---

### 5. GVMManagement
**Location:** `src/components/GVMManagement.tsx`

**Purpose:** Greenbone Vulnerability Manager (GVM/OpenVAS) integration for vulnerability scanning and management.

**Features:**
- Start/stop vulnerability scans
- View scan results with CVSS scores
- Filter by severity (Critical, High, Medium, Low)
- Detailed vulnerability information
- Remediation recommendations

**Key Types:**
```typescript
interface Vulnerability {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss: number;
  host: string;
  port: string;
  description: string;
  solution?: string;
}

interface ScanTask {
  id: string;
  name: string;
  target: string;
  status: 'running' | 'completed' | 'failed' | 'stopped';
  progress: number;
  startTime: string;
  endTime?: string;
}
```

**Usage Example:**
```tsx
import { GVMManagement } from '@/components/GVMManagement';

function VulnScanPage() {
  return (
    <div className="container mx-auto p-6">
      <h1 className="text-3xl font-bold mb-6">Vulnerability Management</h1>
      <GVMManagement />
    </div>
  );
}
```

**API Integration:**
```typescript
import { startGVMScan, getGVMResults } from '@/services/securityApi';

const handleStartScan = async (target: string) => {
  try {
    const result = await startGVMScan({ target });
    toast.success('Scan started successfully');
  } catch (error) {
    toast.error('Failed to start scan');
  }
};
```

---

### 6. IppsYChatPane
**Location:** `src/components/IppsYChatPane.tsx`

**Purpose:** AI-powered chat assistant for security guidance and support.

**Features:**
- Natural language interaction
- Security-specific knowledge
- Command suggestions
- Chat history persistence
- Code snippet generation

**Key Props:**
```typescript
interface IppsYChatPaneProps {
  onCommandExecute?: (command: string) => void;
  contextData?: Record<string, any>;
}
```

**Usage Example:**
```tsx
import { IppsYChatPane } from '@/components/IppsYChatPane';

function ChatPage() {
  const handleCommand = (cmd: string) => {
    console.log('Executing:', cmd);
  };

  return (
    <IppsYChatPane 
      onCommandExecute={handleCommand}
      contextData={{ currentScan: 'scan-123' }}
    />
  );
}
```

---

### 7. ConnectionStatusIndicator
**Location:** `src/components/ConnectionStatusIndicator.tsx`

**Purpose:** Visual indicator showing real-time connection status to backend services.

**Features:**
- Color-coded status (green = connected, red = disconnected, yellow = connecting)
- Tooltip with service details
- Auto-refresh every 30 seconds
- Error state handling

**Key Props:**
```typescript
interface ConnectionStatusIndicatorProps {
  serviceName: string;
  status: 'connected' | 'disconnected' | 'connecting' | 'error';
  lastChecked?: string;
}
```

**Usage Example:**
```tsx
import { ConnectionStatusIndicator } from '@/components/ConnectionStatusIndicator';
import { useSecurityStatus } from '@/hooks/useSecurityStatus';

function Header() {
  const { gvmStatus, spiderfootStatus } = useSecurityStatus();

  return (
    <header className="flex gap-2">
      <ConnectionStatusIndicator 
        serviceName="GVM"
        status={gvmStatus}
      />
      <ConnectionStatusIndicator 
        serviceName="Spiderfoot"
        status={spiderfootStatus}
      />
    </header>
  );
}
```

---

### 8. EnvironmentConfigStatus
**Location:** `src/components/EnvironmentConfigStatus.tsx`

**Purpose:** Displays current environment configuration and service availability.

**Features:**
- Service endpoint display
- Configuration validation
- Environment mode indicator (dev/staging/prod)
- Health check status

**Usage Example:**
```tsx
import { EnvironmentConfigStatus } from '@/components/EnvironmentConfigStatus';

function SettingsPage() {
  return (
    <div className="container mx-auto p-6">
      <h1 className="text-3xl font-bold mb-6">System Configuration</h1>
      <EnvironmentConfigStatus />
    </div>
  );
}
```

---

## Service Layer

### 1. securityApi.ts
**Location:** `src/services/securityApi.ts`

**Purpose:** Core security API client for GVM and Spiderfoot integration.

**Key Functions:**

```typescript
// GVM Functions
export const startGVMScan = async (params: GVMScanParams): Promise<GVMScanResult> => {
  const response = await fetch(`${API_BASE_URL}/openvas/start-scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  return response.json();
};

export const getGVMResults = async (scanId: string): Promise<GVMResults> => {
  const response = await fetch(`${API_BASE_URL}/openvas/results/${scanId}`);
  return response.json();
};

// Spiderfoot OSINT Functions
export const startSpiderfootScan = async (target: string): Promise<SpiderfootScanResult> => {
  const response = await fetch(`${API_BASE_URL}/spiderfoot/scan`, {
    method: 'POST',
    body: JSON.stringify({ target }),
  });
  return response.json();
};

export const checkServiceHealth = async (service: string): Promise<HealthStatus> => {
  const response = await fetch(`${API_BASE_URL}/${service}/health`);
  return response.json();
};
```

**Error Handling:**
```typescript
try {
  const result = await startGVMScan({ target: '192.168.1.1' });
} catch (error) {
  if (error instanceof NetworkError) {
    // Handle network error
  } else if (error instanceof AuthError) {
    // Handle authentication error
  }
}
```

---

### 2. agenticPentestApi.ts
**Location:** `src/services/agenticPentestApi.ts`

**Purpose:** API client for AI-powered penetration testing features.

**Key Functions:**

```typescript
export const generateAttackPlan = async (
  target: string,
  mode: ScanMode,
  tools: string[]
): Promise<AttackPlan> => {
  const response = await fetch(`${API_BASE_URL}/pentest/plan`, {
    method: 'POST',
    body: JSON.stringify({ target, mode, tools }),
  });
  return response.json();
};

export const executeAttackPlan = async (
  planId: string,
  options?: ExecutionOptions
): Promise<ExecutionResult> => {
  const response = await fetch(`${API_BASE_URL}/pentest/execute/${planId}`, {
    method: 'POST',
    body: JSON.stringify(options),
  });
  return response.json();
};

export const getVulnerabilityAnalysis = async (
  scanResults: ScanResult[]
): Promise<VulnerabilityAnalysis> => {
  const response = await fetch(`${API_BASE_URL}/pentest/analyze`, {
    method: 'POST',
    body: JSON.stringify({ results: scanResults }),
  });
  return response.json();
};
```

---

### 3. openaiService.ts
**Location:** `src/services/openaiService.ts`

**Purpose:** OpenAI/AI integration service for chat and content generation.

**Key Functions:**

```typescript
export const sendChatMessage = async (
  message: string,
  context?: ChatContext
): Promise<ChatResponse> => {
  const { data, error } = await supabase.functions.invoke('ippsy-chat', {
    body: { message, context }
  });
  
  if (error) throw error;
  return data;
};

export const generateReport = async (
  findings: Finding[],
  template: string
): Promise<GeneratedReport> => {
  const { data, error } = await supabase.functions.invoke('generate-report', {
    body: { findings, template }
  });
  
  if (error) throw error;
  return data;
};
```

---

### 4. enhancedSecurityService.ts
**Location:** `src/services/enhancedSecurityService.ts`

**Purpose:** Enhanced security service with circuit breaker pattern and health monitoring.

**Features:**
- Circuit breaker for fault tolerance
- Automatic retry logic
- Health check aggregation
- Service status monitoring

**Key Functions:**

```typescript
export const getAggregatedSecurityStatus = async (): Promise<SecurityStatus> => {
  const [gvm, spiderfoot] = await Promise.allSettled([
    checkServiceHealth('gvm'),
    checkServiceHealth('spiderfoot'),
  ]);
  
  return {
    gvm: gvm.status === 'fulfilled' ? gvm.value : { status: 'error' },
    spiderfoot: spiderfoot.status === 'fulfilled' ? spiderfoot.value : { status: 'error' },
    overall: calculateOverallHealth([gvm, spiderfoot]),
  };
};

export const executeWithCircuitBreaker = async <T>(
  fn: () => Promise<T>,
  service: string
): Promise<T> => {
  const breaker = circuitBreakers[service];
  
  if (breaker.isOpen()) {
    throw new Error(`Circuit breaker open for ${service}`);
  }
  
  try {
    const result = await fn();
    breaker.recordSuccess();
    return result;
  } catch (error) {
    breaker.recordFailure();
    throw error;
  }
};
```

---

## Hooks & State Management

### 1. useSecurityStatus
**Location:** `src/hooks/useSecurityStatus.ts`

**Purpose:** Custom hook for monitoring security service status.

**Returns:**
```typescript
interface SecurityStatusHook {
  gvmStatus: 'connected' | 'disconnected' | 'error';
  spiderfootStatus: 'connected' | 'disconnected' | 'error';
  isLoading: boolean;
  error: Error | null;
  refetch: () => void;
}
```

**Usage Example:**
```tsx
import { useSecurityStatus } from '@/hooks/useSecurityStatus';

function StatusDisplay() {
  const { gvmStatus, spiderfootStatus, isLoading, refetch } = useSecurityStatus();

  if (isLoading) return <Spinner />;

  return (
    <div>
      <p>GVM: {gvmStatus}</p>
      <p>Spiderfoot: {spiderfootStatus}</p>
      <Button onClick={refetch}>Refresh</Button>
    </div>
  );
}
```

---

### 2. useRealTimeSecurityData
**Location:** `src/hooks/useRealTimeSecurityData.ts`

**Purpose:** Real-time security metrics with WebSocket/polling support.

**Returns:**
```typescript
interface RealTimeSecurityData {
  metrics: SecurityMetrics;
  alerts: Alert[];
  isConnected: boolean;
  lastUpdate: string;
}
```

**Usage Example:**
```tsx
import { useRealTimeSecurityData } from '@/hooks/useRealTimeSecurityData';

function MetricsDashboard() {
  const { metrics, alerts, isConnected } = useRealTimeSecurityData();

  return (
    <div>
      <Badge variant={isConnected ? 'success' : 'destructive'}>
        {isConnected ? 'Live' : 'Disconnected'}
      </Badge>
      <div className="grid grid-cols-3 gap-4">
        <MetricCard title="Vulnerabilities" value={metrics.vulnerabilities} />
        <MetricCard title="Active Scans" value={metrics.activeScans} />
        <MetricCard title="Alerts" value={alerts.length} />
      </div>
    </div>
  );
}
```

---

### 3. use-toast
**Location:** `src/hooks/use-toast.ts`

**Purpose:** Toast notification hook for user feedback.

**Usage Example:**
```tsx
import { useToast } from '@/hooks/use-toast';

function ActionButton() {
  const { toast } = useToast();

  const handleAction = async () => {
    try {
      await performAction();
      toast({
        title: 'Success',
        description: 'Action completed successfully',
        variant: 'default',
      });
    } catch (error) {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive',
      });
    }
  };

  return <Button onClick={handleAction}>Perform Action</Button>;
}
```

---

### 4. use-mobile
**Location:** `src/hooks/use-mobile.tsx`

**Purpose:** Responsive breakpoint detection hook.

**Usage Example:**
```tsx
import { useMobile } from '@/hooks/use-mobile';

function ResponsiveComponent() {
  const isMobile = useMobile();

  return (
    <div className={isMobile ? 'flex-col' : 'flex-row'}>
      {/* Responsive content */}
    </div>
  );
}
```

---

## Type Definitions

### 1. security.ts
**Location:** `src/types/security.ts`

**Core Security Types:**

```typescript
export interface Vulnerability {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss: number;
  cvssVector?: string;
  host: string;
  port: string;
  protocol: string;
  service?: string;
  solution?: string;
  references?: string[];
  detectedAt: string;
}

export interface SecurityMetrics {
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  averageCVSS: number;
  hostsScanned: number;
  lastScanDate: string;
}

export interface ScanTask {
  id: string;
  name: string;
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'stopped';
  progress: number;
  startTime: string;
  endTime?: string;
  scanType: 'quick' | 'standard' | 'deep' | 'custom';
  vulnerabilitiesFound: number;
  errors?: string[];
}

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'down';
  responseTime: number;
  lastChecked: string;
  version?: string;
  message?: string;
}
```

---

### 2. agenticPentest.ts
**Location:** `src/types/agenticPentest.ts`

**Penetration Testing Types:**

```typescript
export interface AttackPlan {
  id: string;
  target: string;
  mode: ScanMode;
  phases: AttackPhase[];
  estimatedDuration: number;
  tools: AttackTool[];
  createdAt: string;
  status: 'draft' | 'approved' | 'executing' | 'completed' | 'failed';
}

export interface AttackPhase {
  id: string;
  name: string;
  description: string;
  order: number;
  commands: Command[];
  expectedOutcome: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  startTime?: string;
  endTime?: string;
  output?: string;
}

export interface Command {
  id: string;
  tool: string;
  command: string;
  parameters: Record<string, any>;
  timeout: number;
  retryCount: number;
}

export interface ExecutionResult {
  planId: string;
  status: 'success' | 'partial' | 'failed';
  completedPhases: string[];
  failedPhases: string[];
  findings: Finding[];
  logs: ExecutionLog[];
  duration: number;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss?: number;
  affectedAssets: string[];
  proofOfConcept?: string;
  remediation: string;
  references: string[];
  discoveredAt: string;
  phase: string;
  tool: string;
}
```

---

### 3. reporting.ts
**Location:** `src/types/reporting.ts`

**Report Generation Types:**

```typescript
export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  category: 'executive' | 'technical' | 'compliance';
  sections: ReportSection[];
  metadata: {
    author: string;
    version: string;
    createdAt: string;
    updatedAt: string;
  };
}

export interface ReportSection {
  id: string;
  title: string;
  order: number;
  type: 'summary' | 'findings' | 'metrics' | 'recommendations' | 'custom';
  required: boolean;
  content?: string;
}

export interface GeneratedReport {
  id: string;
  title: string;
  template: string;
  generatedAt: string;
  generatedBy: string;
  content: ReportContent;
  findings: Finding[];
  metrics: SecurityMetrics;
  format: 'markdown' | 'html' | 'pdf';
  status: 'draft' | 'final';
}

export interface ReportContent {
  executiveSummary?: string;
  methodology?: string;
  findings: Finding[];
  riskAssessment?: RiskAssessment;
  recommendations: Recommendation[];
  appendices?: Appendix[];
}

export interface Recommendation {
  id: string;
  title: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  estimatedEffort: string;
  expectedImpact: string;
  relatedFindings: string[];
}
```

---

## Integration Patterns

### Backend API Integration

**Pattern 1: Direct API Calls**
```typescript
// services/securityApi.ts
export const fetchData = async (): Promise<Data> => {
  const response = await fetch(`${API_BASE_URL}/endpoint`);
  if (!response.ok) throw new Error('API Error');
  return response.json();
};

// Component usage
const MyComponent = () => {
  const [data, setData] = useState<Data | null>(null);
  
  useEffect(() => {
    fetchData().then(setData).catch(console.error);
  }, []);
  
  return <div>{data?.value}</div>;
};
```

**Pattern 2: TanStack Query (Recommended)**
```typescript
import { useQuery } from '@tanstack/react-query';
import { fetchData } from '@/services/securityApi';

const MyComponent = () => {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['data'],
    queryFn: fetchData,
    refetchInterval: 30000, // 30 seconds
  });
  
  if (isLoading) return <Spinner />;
  if (error) return <ErrorDisplay error={error} />;
  
  return <div>{data?.value}</div>;
};
```

---

### Supabase Integration

**Pattern 1: Edge Function Call**
```typescript
import { supabase } from '@/integrations/supabase/client';

const callEdgeFunction = async (params: Params) => {
  const { data, error } = await supabase.functions.invoke('function-name', {
    body: params
  });
  
  if (error) throw error;
  return data;
};
```

**Pattern 2: Real-time Subscription**
```typescript
import { supabase } from '@/integrations/supabase/client';
import { useEffect, useState } from 'react';

const useRealtimeData = () => {
  const [data, setData] = useState([]);
  
  useEffect(() => {
    const channel = supabase
      .channel('table-changes')
      .on('postgres_changes', 
        { event: '*', schema: 'public', table: 'my_table' },
        (payload) => {
          console.log('Change received!', payload);
          // Update local state
        }
      )
      .subscribe();
    
    return () => {
      supabase.removeChannel(channel);
    };
  }, []);
  
  return data;
};
```

---

## Routing & Navigation

**Router Configuration:** `src/App.tsx`

```tsx
import { BrowserRouter, Routes, Route } from "react-router-dom";

const App = () => (
  <BrowserRouter>
    <Routes>
      <Route path="/" element={<Index />} />
      <Route path="/gvm" element={<GVMManagement />} />
      <Route path="/status" element={<SystemStatus />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  </BrowserRouter>
);
```

**Navigation Example:**
```tsx
import { Link, useNavigate } from 'react-router-dom';

function Navigation() {
  const navigate = useNavigate();

  const handleNavigation = () => {
    navigate('/gvm');
  };

  return (
    <nav>
      <Link to="/">Dashboard</Link>
      <Link to="/gvm">Vulnerability Management</Link>
      <Link to="/status">System Status</Link>
      <Button onClick={handleNavigation}>Go to GVM</Button>
    </nav>
  );
}
```

---

## Best Practices

### 1. Component Design
- **Single Responsibility**: Each component should have one clear purpose
- **Composition over Inheritance**: Use composition patterns for reusability
- **Props Interface**: Always define TypeScript interfaces for props
- **Default Values**: Provide sensible defaults for optional props

```tsx
interface ButtonProps {
  variant?: 'default' | 'destructive' | 'outline';
  size?: 'sm' | 'md' | 'lg';
  onClick: () => void;
  children: React.ReactNode;
}

const Button = ({ 
  variant = 'default', 
  size = 'md', 
  onClick, 
  children 
}: ButtonProps) => {
  return (
    <button 
      className={cn(buttonVariants({ variant, size }))}
      onClick={onClick}
    >
      {children}
    </button>
  );
};
```

---

### 2. State Management
- **Local State**: Use `useState` for component-specific state
- **Server State**: Use TanStack Query for server data
- **Global State**: Consider Context API for shared state
- **Form State**: Use `react-hook-form` for complex forms

```tsx
// Local state
const [count, setCount] = useState(0);

// Server state
const { data } = useQuery({
  queryKey: ['users'],
  queryFn: fetchUsers
});

// Form state
import { useForm } from 'react-hook-form';

const { register, handleSubmit } = useForm();
```

---

### 3. Error Handling
- **Try-Catch**: Always wrap async operations
- **User Feedback**: Show toast notifications for errors
- **Error Boundaries**: Implement for catastrophic failures
- **Logging**: Log errors to monitoring service

```tsx
import { useToast } from '@/hooks/use-toast';

function Component() {
  const { toast } = useToast();

  const handleAction = async () => {
    try {
      await riskyOperation();
      toast({ title: 'Success', description: 'Operation completed' });
    } catch (error) {
      console.error('Operation failed:', error);
      toast({ 
        title: 'Error', 
        description: error.message,
        variant: 'destructive' 
      });
    }
  };
}
```

---

### 4. Performance Optimization
- **Memoization**: Use `useMemo` and `useCallback` for expensive computations
- **Code Splitting**: Lazy load routes and heavy components
- **Debouncing**: Debounce search inputs and API calls
- **Virtualization**: Use virtual lists for large datasets

```tsx
import { useMemo, useCallback } from 'react';
import { lazy, Suspense } from 'react';

// Memoization
const expensiveValue = useMemo(() => computeExpensiveValue(data), [data]);

const handleClick = useCallback(() => {
  doSomething(a, b);
}, [a, b]);

// Lazy loading
const HeavyComponent = lazy(() => import('./HeavyComponent'));

function App() {
  return (
    <Suspense fallback={<Loading />}>
      <HeavyComponent />
    </Suspense>
  );
}
```

---

### 5. Accessibility
- **Semantic HTML**: Use appropriate HTML elements
- **ARIA Labels**: Add labels for screen readers
- **Keyboard Navigation**: Ensure all interactions are keyboard-accessible
- **Focus Management**: Manage focus states properly

```tsx
<button 
  aria-label="Close dialog"
  aria-pressed={isPressed}
  role="button"
  tabIndex={0}
  onKeyDown={(e) => e.key === 'Enter' && handleClick()}
>
  Close
</button>
```

---

### 6. Testing Considerations
- **Component Tests**: Test component rendering and behavior
- **Integration Tests**: Test component interactions
- **E2E Tests**: Test critical user flows
- **Mock Data**: Create realistic mock data for development

```tsx
// Mock data example
export const mockVulnerabilities: Vulnerability[] = [
  {
    id: 'vuln-1',
    name: 'SQL Injection',
    severity: 'critical',
    cvss: 9.8,
    host: '192.168.1.100',
    port: '3306',
    description: 'SQL injection vulnerability in login form',
    solution: 'Use parameterized queries',
    detectedAt: new Date().toISOString(),
  },
  // ... more mock data
];
```

---

## Configuration

### Environment Variables
**File:** `.env` (auto-generated)

```env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=your-anon-key
VITE_SUPABASE_PROJECT_ID=your-project-id
```

**Usage in Code:**
```typescript
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
```

---

### Service Configuration
**File:** `src/config/environment.ts`

```typescript
export const serviceConfig = {
  gvm: {
    baseUrl: 'http://localhost:9392',
    timeout: 30000,
    enabled: true,
  },
  spiderfoot: {
    baseUrl: 'http://localhost:5001',
    timeout: 60000,
    enabled: true,
  },
};
```

---

## Troubleshooting

### Common Issues

**Issue 1: Connection Status Always Shows Disconnected**
- Check if backend services are running
- Verify API URLs in `environment.ts`
- Check browser console for CORS errors
- Ensure health check endpoints are accessible

**Issue 2: Toast Notifications Not Appearing**
- Verify `<Toaster />` is rendered in App.tsx
- Check if `useToast` hook is imported correctly
- Ensure toast component is not hidden by CSS z-index

**Issue 3: Type Errors with Supabase**
- Never manually edit `src/integrations/supabase/types.ts`
- Regenerate types after database migrations
- Check if database tables match type definitions

**Issue 4: Real-time Updates Not Working**
- Enable realtime on Supabase tables
- Check if RLS policies allow realtime subscriptions
- Verify channel subscription is active

---

## Deployment Checklist

- [ ] Update environment variables for production
- [ ] Build production bundle: `npm run build`
- [ ] Test production build locally
- [ ] Configure CORS for production API
- [ ] Set up error monitoring (Sentry, etc.)
- [ ] Enable analytics tracking
- [ ] Configure CDN for static assets
- [ ] Set up SSL certificates
- [ ] Test on multiple browsers and devices
- [ ] Verify SEO meta tags
- [ ] Check performance metrics (Lighthouse)
- [ ] Set up automated backups

---

## Additional Resources

- [React Documentation](https://react.dev)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [Tailwind CSS Docs](https://tailwindcss.com/docs)
- [shadcn/ui Components](https://ui.shadcn.com)
- [TanStack Query Docs](https://tanstack.com/query/latest)
- [Vite Guide](https://vitejs.dev/guide/)

---

**Last Updated:** 2025-10-12
**Version:** 1.0.0
**Maintainer:** IPS Security Team
