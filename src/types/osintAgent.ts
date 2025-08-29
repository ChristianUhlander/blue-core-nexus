/**
 * OSINT Agent Types & Interfaces
 * Encrypted Intelligence Gathering System
 */

export interface OSINTTool {
  name: string;
  version: string;
  enabled: boolean;
  category: 'social' | 'domain' | 'email' | 'phone' | 'image' | 'document' | 'network' | 'geoint' | 'financial';
  description: string;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  requiresAuth: boolean;
  legalCompliance: boolean;
  configuration: Record<string, any>;
}

export interface OSINTTarget {
  id: string;
  type: 'person' | 'organization' | 'domain' | 'ip' | 'phone' | 'email' | 'image' | 'document';
  value: string;
  metadata: Record<string, any>;
  createdAt: number;
  lastUpdated: number;
  encrypted: boolean;
}

export interface OSINTResult {
  id: string;
  targetId: string;
  toolUsed: string;
  category: string;
  confidence: number;
  data: any;
  sources: string[];
  timestamp: number;
  encrypted: boolean;
  verified: boolean;
  sensitive: boolean;
}

export interface OSINTInvestigation {
  id: string;
  name: string;
  description: string;
  targets: OSINTTarget[];
  results: OSINTResult[];
  status: 'planning' | 'active' | 'paused' | 'completed' | 'archived';
  priority: 'low' | 'medium' | 'high' | 'critical';
  createdAt: number;
  lastActivity: number;
  encryptionEnabled: boolean;
  complianceLevel: 'standard' | 'gdpr' | 'ccpa' | 'government';
  tags: string[];
}

export interface OSINTScenario {
  id: string;
  name: string;
  description: string;
  category: 'corporate' | 'personal' | 'threat-hunting' | 'due-diligence' | 'fraud' | 'security';
  difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert';
  tools: string[];
  workflow: OSINTWorkflowStep[];
  legalConsiderations: string[];
  estimatedTime: number; // minutes
}

export interface OSINTWorkflowStep {
  id: string;
  name: string;
  description: string;
  tool: string;
  parameters: Record<string, any>;
  dependsOn: string[];
  optional: boolean;
  automatable: boolean;
}

export interface OSINTReport {
  id: string;
  investigationId: string;
  title: string;
  summary: string;
  findings: OSINTFinding[];
  methodology: string[];
  sources: string[];
  confidenceScore: number;
  riskAssessment: string;
  recommendations: string[];
  createdAt: number;
  encrypted: boolean;
  classification: 'public' | 'internal' | 'confidential' | 'restricted';
}

export interface OSINTFinding {
  id: string;
  category: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  evidence: any[];
  confidence: number;
  sources: string[];
  verified: boolean;
  timestamp: number;
}

export interface OSINTConfiguration {
  apiKeys: Record<string, string>;
  proxies: ProxyConfig[];
  userAgents: string[];
  delays: DelayConfig;
  compliance: ComplianceConfig;
  encryption: EncryptionConfig;
  notifications: NotificationConfig;
}

export interface ProxyConfig {
  type: 'http' | 'socks4' | 'socks5';
  host: string;
  port: number;
  username?: string;
  password?: string;
  enabled: boolean;
}

export interface DelayConfig {
  minDelay: number;
  maxDelay: number;
  requestsPerMinute: number;
  respectRobotsTxt: boolean;
}

export interface ComplianceConfig {
  gdprCompliant: boolean;
  ccpaCompliant: boolean;
  dataRetentionDays: number;
  requireConsent: boolean;
  anonymizeData: boolean;
  logActivities: boolean;
}

export interface EncryptionConfig {
  encryptionEnabled: boolean;
  keyRotationDays: number;
  encryptAtRest: boolean;
  encryptInTransit: boolean;
  encryptReports: boolean;
}

export interface NotificationConfig {
  emailAlerts: boolean;
  slackIntegration: boolean;
  webhookUrl?: string;
  alertThreshold: 'low' | 'medium' | 'high';
}

export interface OSINTSource {
  name: string;
  url: string;
  category: string;
  apiEndpoint?: string;
  rateLimit?: number;
  requiresAuth: boolean;
  trustScore: number;
  lastChecked: number;
  active: boolean;
}

export interface OSINTMetrics {
  totalInvestigations: number;
  activeInvestigations: number;
  totalTargets: number;
  totalResults: number;
  averageConfidence: number;
  topTools: { name: string; usage: number }[];
  successRate: number;
  complianceScore: number;
}

// AI-Enhanced OSINT Features
export interface AIAnalysis {
  id: string;
  type: 'pattern-detection' | 'anomaly-detection' | 'relationship-mapping' | 'risk-assessment';
  input: any;
  output: any;
  confidence: number;
  model: string;
  timestamp: number;
  encrypted: boolean;
}

export interface IntelligenceGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  metadata: {
    createdAt: number;
    lastUpdated: number;
    nodeCount: number;
    edgeCount: number;
    encrypted: boolean;
  };
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  properties: Record<string, any>;
  risk: number;
  verified: boolean;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  weight: number;
  properties: Record<string, any>;
  verified: boolean;
}