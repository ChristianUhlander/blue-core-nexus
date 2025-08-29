/**
 * Penetration Testing Types and Interfaces
 * K8s Security Assessment Framework
 */

// Target Types for K8s Environment
export interface K8sTarget {
  type: 'pod' | 'service' | 'ingress' | 'node' | 'external';
  name: string;
  namespace?: string;
  ip: string;
  ports: number[];
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

export interface PenetrationTarget {
  id: string;
  name: string;
  type: 'k8s' | 'external' | 'network_range';
  targets: K8sTarget[];
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  scope: string[];
  exclusions: string[];
  created: string;
  lastTested?: string;
}

// Tool Configurations
export interface MetasploitConfig {
  workspace: string;
  payload: string;
  encoder?: string;
  platform: string;
  architecture: string;
  sessions: boolean;
  logging: boolean;
}

export interface NmapConfig {
  scanType: 'tcp_syn' | 'tcp_connect' | 'udp' | 'stealth' | 'comprehensive';
  ports: string; // e.g., "1-1000", "80,443,8080"
  timing: '0' | '1' | '2' | '3' | '4' | '5'; // T0-T5
  scripts: string[];
  osDetection: boolean;
  serviceVersion: boolean;
  aggressive: boolean;
  outputFormat: 'xml' | 'json' | 'gnmap';
}

export interface BurpConfig {
  scope: string[];
  spiderConfig: {
    maxDepth: number;
    threads: number;
    timeout: number;
  };
  scannerConfig: {
    scanSpeed: 'thorough' | 'normal' | 'fast';
    scanAccuracy: 'normal' | 'minimize_false_positives' | 'minimize_false_negatives';
  };
  extensions: string[];
}

// Test Results and Evidence
export interface PentestEvidence {
  id: string;
  testId: string;
  type: 'screenshot' | 'log' | 'payload' | 'output' | 'file';
  title: string;
  content: string | Buffer;
  timestamp: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  tags: string[];
}

export interface PentestFinding {
  id: string;
  title: string;
  description: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  cvss: {
    score: number;
    vector: string;
    attackVector: 'network' | 'adjacent' | 'local' | 'physical';
    attackComplexity: 'low' | 'high';
    privilegesRequired: 'none' | 'low' | 'high';
    userInteraction: 'none' | 'required';
    scope: 'unchanged' | 'changed';
    confidentiality: 'none' | 'low' | 'high';
    integrity: 'none' | 'low' | 'high';
    availability: 'none' | 'low' | 'high';
  };
  impact: string;
  poc: string; // Proof of concept
  remediation: string;
  references: string[];
  evidence: PentestEvidence[];
  target: K8sTarget;
  tool: string;
  created: string;
  status: 'open' | 'confirmed' | 'false_positive' | 'accepted_risk' | 'fixed';
}

// K8s Specific Security Tests
export interface K8sSecurityTest {
  id: string;
  name: string;
  category: 'rbac' | 'network_policy' | 'pod_security' | 'secrets' | 'container_escape' | 'privilege_escalation';
  description: string;
  technique: string; // MITRE ATT&CK technique
  prerequisites: string[];
  steps: K8sTestStep[];
  expectedResults: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  automated: boolean;
}

export interface K8sTestStep {
  id: string;
  action: 'kubectl' | 'curl' | 'script' | 'manual';
  command?: string;
  script?: string;
  description: string;
  expectedOutput?: string;
  verification: string;
}

// Penetration Test Session
export interface PentestSession {
  id: string;
  name: string;
  description: string;
  targets: PenetrationTarget[];
  scope: string[];
  methodology: 'owasp' | 'nist' | 'ptes' | 'osstmm' | 'custom';
  phase: 'reconnaissance' | 'scanning' | 'enumeration' | 'exploitation' | 'post_exploitation' | 'reporting';
  status: 'planned' | 'active' | 'paused' | 'completed' | 'cancelled';
  findings: PentestFinding[];
  tools: {
    metasploit: MetasploitConfig;
    nmap: NmapConfig;
    burp: BurpConfig;
    custom: Record<string, any>;
  };
  timeline: {
    started: string;
    estimated_completion: string;
    actual_completion?: string;
  };
  team: {
    lead: string;
    members: string[];
  };
  evidence: PentestEvidence[];
  report?: {
    executive_summary: string;
    technical_details: string;
    recommendations: string;
    generated: string;
    format: 'pdf' | 'html' | 'markdown';
  };
}

// Tool Integration Status
export interface PentestToolStatus {
  metasploit: {
    connected: boolean;
    version?: string;
    workspaces: string[];
    modules: number;
    payloads: number;
  };
  nmap: {
    connected: boolean;
    version?: string;
    scripts: string[];
  };
  burp: {
    connected: boolean;
    version?: string;
    extensions: string[];
    projects: string[];
  };
  custom: Record<string, {
    connected: boolean;
    version?: string;
    capabilities: string[];
  }>;
}

// API Response Types
export interface PentestApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
  sessionId?: string;
}

// WebSocket Message Types for Real-time Updates
export interface PentestWSMessage {
  type: 'scan_progress' | 'finding_discovered' | 'tool_status' | 'session_update';
  sessionId: string;
  data: any;
  timestamp: string;
}