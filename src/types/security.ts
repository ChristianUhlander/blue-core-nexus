/**
 * Security Service Type Definitions
 * Backend Integration: Security services API definitions
 */

// Service Configuration Types
export interface ServiceConfig {
  name: string;
  endpoint: string;
  protocol: 'http' | 'https' | 'ws' | 'wss';
  port: number;
  healthPath: string;
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
}

// Connection Status Types
export interface ConnectionStatus {
  online: boolean;
  lastCheck: string | null;
  error: string | null;
  responseTime: number;
  retryCount: number;
  version?: string;
}

// Service Status Types
export interface WazuhStatus extends ConnectionStatus {
  agents: number;
  activeAgents: number;
  alerts: number;
  criticalAlerts: number;
  lastAlert?: string;
}

export interface GVMStatus extends ConnectionStatus {
  scans: number;
  activeScans: number;
  totalTasks: number;
  vulnerabilities: number;
  lastScan?: string;
}



// Alert Types
export interface SecurityAlert {
  id: string;
  source: 'wazuh' | 'gvm';
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  agentId?: string;
  agentName?: string;
  rule?: {
    id: string;
    description: string;
    level: number;
  };
  data?: Record<string, any>;
  acknowledged: boolean;
  assignedTo?: string;
}

// Wazuh Types
export interface WazuhAgent {
  id: string;
  name: string;
  ip: string;
  status: 'active' | 'disconnected' | 'never_connected' | 'pending';
  os: {
    platform: string;
    version: string;
    name: string;
  };
  version: string;
  lastKeepAlive?: string;
  nodeName?: string;
  dateAdd: string;
  manager?: string;
  group?: string[];
}

export interface WazuhAlert {
  id: string;
  timestamp: string;
  ruleId: string;
  ruleLevel: number;
  ruleDescription: string;
  agentId: string;
  agentName: string;
  location: string;
  srcIp?: string;
  dstIp?: string;
  fullLog: string;
  mitre?: {
    id: string[];
    tactic: string[];
    technique: string[];
  };
}

// Scan Types
export interface ScanConfig {
  id: string;
  name: string;
  target: string;
  type: 'baseline' | 'full' | 'custom';
  options: Record<string, any>;
  schedule?: {
    enabled: boolean;
    cron: string;
  };
}

export interface ScanResult {
  id: string;
  configId: string;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  startTime: string;
  endTime?: string;
  progress: number;
  findings: Finding[];
  metadata: Record<string, any>;
}

export interface Finding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  impact: string;
  solution: string;
  reference: string[];
  cve?: string[];
  cvss?: {
    score: number;
    vector: string;
  };
}

// Service Endpoint Configuration
export interface ServiceEndpoint {
  namespace: string;
  serviceName: string;
  port: number;
  path?: string;
}

// API Response Types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
  requestId: string;
}

// WebSocket Message Types
export interface WSMessage {
  type: 'alert' | 'status' | 'scan_progress' | 'agent_update';
  source: string;
  data: any;
  timestamp: string;
}

// GVM Types
export interface GvmTarget {
  id: string;
  name: string;
  hosts: string[];
  comment?: string;
  port_list_id?: string;
}

export interface GvmTask {
  id: string;
  name: string;
  status: 'New' | 'Running' | 'Stopped' | 'Done';
  progress: number;
  target: {
    id: string;
    name: string;
  };
  config: {
    id: string;
    name: string;
  };
  last_report?: {
    id: string;
    timestamp: string;
  };
  comment?: string;
}