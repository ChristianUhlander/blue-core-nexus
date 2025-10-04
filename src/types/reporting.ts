// Enhanced Report Template
export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  sections: ReportSection[];
  format: ReportFormat;
  customizable: boolean;
  version: string;
  createdAt: Date;
  updatedAt: Date;
  metadata: {
    estimatedTokens: number;
    avgGenerationTime: number;
    usageCount: number;
  };
}

export interface ReportSection {
  id: string;
  title: string;
  required: boolean;
  order: number;
  contentType: 'text' | 'table' | 'chart' | 'code';
  promptTemplate: string;
}

export type ReportFormat = 'executive' | 'technical' | 'compliance' | 'developer' | 'custom';

// Enhanced Audience Profile
export interface AudienceProfile {
  id: string;
  name: string;
  type: AudienceType;
  description: string;
  focusAreas: string[];
  technicalLevel: TechnicalLevel;
  preferredFormat: OutputFormat;
  communicationStyle: CommunicationStyle;
  priorityMetrics: string[];
  excludedTopics?: string[];
}

export type AudienceType = 'executive' | 'technical' | 'compliance' | 'developer' | 'custom';
export type TechnicalLevel = 'low' | 'medium' | 'high';
export type OutputFormat = 'summary' | 'detailed' | 'reference';
export type CommunicationStyle = 'formal' | 'technical' | 'business' | 'educational';

// Comprehensive Report Data
export interface ReportData {
  vulnerabilities: SecurityVulnerability[];
  scanResults: ScanResult[];
  complianceStatus: ComplianceCheck[];
  metrics: SecurityMetrics;
  trends: TrendData[];
  recommendations: Recommendation[];
  research?: ResearchData;
  timeRange: TimeRange;
  dataSourceMetadata: DataSourceMetadata[];
}

export interface SecurityVulnerability {
  id: string;
  cveId?: string;
  title: string;
  description: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  cvssScore: number;
  cvssVector?: string;
  affectedSystems: string[];
  discoveredAt: Date;
  status: 'Open' | 'In Progress' | 'Resolved' | 'Accepted';
  attackVector?: string;
  exploitability?: 'Functional' | 'POC' | 'Unproven';
  cwe?: string;
  regulatoryImpact?: string[];
  businessImpact?: string;
  remediationSteps?: string[];
  fixComplexity?: 'Low' | 'Medium' | 'High';
  codeLocation?: string;
}

export interface ScanResult {
  id: string;
  scanType: 'OWASP' | 'Network' | 'Infrastructure' | 'Code' | 'Container';
  timestamp: Date;
  status: 'Completed' | 'In Progress' | 'Failed';
  findings: number;
  breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  coverage: number;
  duration: number;
  targetInfo: {
    name: string;
    type: string;
    location: string;
  };
}

export interface ComplianceCheck {
  id: string;
  framework: string;
  requirement: string;
  status: 'Compliant' | 'Non-Compliant' | 'Partial' | 'Not Applicable';
  score: number;
  gaps: string[];
  evidence?: string[];
  lastChecked: Date;
  nextReview: Date;
  owner: string;
}

export interface SecurityMetrics {
  riskScore: number;
  riskTrend: 'improving' | 'stable' | 'degrading';
  vulnerabilityBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  complianceScore: number;
  meanTimeToRemediate: number;
  openVulnerabilities: number;
  resolvedThisPeriod: number;
  securityPosture: 'excellent' | 'good' | 'fair' | 'poor';
}

export interface TrendData {
  period: string;
  vulnerabilities: number;
  remediationRate: number;
  newThreats: number;
  complianceScore: number;
}

export interface Recommendation {
  id: string;
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  category: string;
  title: string;
  description: string;
  impact: string;
  effort: 'Low' | 'Medium' | 'High';
  timeline: string;
  dependencies?: string[];
  resources?: string[];
  successCriteria?: string[];
}

export interface ResearchData {
  perplexityResults?: ExternalSearchResult[];
  cveData?: CVEEntry[];
  mitreAttack?: MITREMapping[];
  threatIntel?: ThreatIntelligence[];
  industryTrends?: IndustryInsight[];
}

export interface ExternalSearchResult {
  source: string;
  title: string;
  url: string;
  snippet: string;
  relevance: number;
  publishDate?: Date;
}

export interface CVEEntry {
  cveId: string;
  description: string;
  cvssScore: number;
  published: Date;
  references: string[];
  affectedProducts: string[];
}

export interface MITREMapping {
  techniqueId: string;
  tacticName: string;
  techniqueName: string;
  description: string;
  detectionMethods: string[];
  mitigations: string[];
}

export interface ThreatIntelligence {
  threatActor?: string;
  campaignName?: string;
  indicators: string[];
  severity: string;
  firstSeen: Date;
  lastSeen: Date;
  targetedSectors: string[];
}

export interface IndustryInsight {
  topic: string;
  summary: string;
  relevance: number;
  sources: string[];
  date: Date;
}

export interface TimeRange {
  start: Date;
  end: Date;
  description: string;
}

export interface DataSourceMetadata {
  source: string;
  lastSync: Date;
  status: 'active' | 'stale' | 'error';
  recordCount: number;
  quality: number;
}

// Job Management
export interface ReportJob {
  id: string;
  reportId?: string;
  status: JobStatus;
  progress: number;
  currentStep: string;
  estimatedTimeRemaining?: number;
  error?: JobError;
  createdAt: Date;
  updatedAt: Date;
  completedAt?: Date;
  metadata: {
    templateId: string;
    audienceId: string;
    requestedBy: string;
    priority: 'low' | 'normal' | 'high';
  };
}

export type JobStatus = 
  | 'initiated' 
  | 'collecting' 
  | 'researching' 
  | 'generating' 
  | 'formatting' 
  | 'completed' 
  | 'failed' 
  | 'cancelled';

export interface JobError {
  code: string;
  message: string;
  details?: any;
  timestamp: Date;
  retryable: boolean;
}

// LLM Configuration
export interface LLMConfig {
  provider: 'openai' | 'perplexity' | 'lovable-ai' | 'local';
  model: string;
  apiKey?: string;
  temperature: number;
  maxTokens: number;
}
