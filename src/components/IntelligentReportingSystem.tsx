import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { toast } from '@/hooks/use-toast';
import { 
  FileText, 
  Brain, 
  Users, 
  Search, 
  Download, 
  Eye, 
  Settings, 
  CheckCircle,
  AlertTriangle,
  TrendingUp,
  Code,
  Shield,
  Target,
  Globe,
  Lightbulb,
  BookOpen,
  Filter,
  RefreshCw,
  Send,
  Sparkles
} from 'lucide-react';

import { createOpenAIService } from '@/services/openaiService';
import { SecurityAssessmentReport } from './SecurityAssessmentReport';
import { 
  ReportTemplate, 
  AudienceProfile, 
  ReportData, 
  LLMConfig, 
  ReportJob,
  JobStatus,
  JobError,
  ReportSection,
  SecurityVulnerability,
  ScanResult,
  ComplianceCheck,
  SecurityMetrics,
  Recommendation
} from '@/types/reporting';

export const IntelligentReportingSystem: React.FC = () => {
  const [activeTab, setActiveTab] = useState('examples');
  const [selectedTemplate, setSelectedTemplate] = useState<string>('');
  const [selectedAudience, setSelectedAudience] = useState<string>('technical');
  const [reportTitle, setReportTitle] = useState('Security Assessment Report');
  const [reportSource, setReportSource] = useState<string>('combined');
  const [isGenerating, setIsGenerating] = useState(false);
  const [generationProgress, setGenerationProgress] = useState(0);
  const [generatedReport, setGeneratedReport] = useState<string>('');
  const [researchQuery, setResearchQuery] = useState('');
  const [researchResults, setResearchResults] = useState<any[]>([]);
  const [reportData, setReportData] = useState<any>(null);
  const [showStructuredReport, setShowStructuredReport] = useState(false);
  
  const [llmConfig, setLlmConfig] = useState<LLMConfig>({
    provider: 'lovable-ai',
    model: 'google/gemini-2.5-flash',
    temperature: 0.3,
    maxTokens: 4000
  });

  const [apiKey, setApiKey] = useState('');
  const [customPrompt, setCustomPrompt] = useState('');
  const [currentJob, setCurrentJob] = useState<ReportJob | null>(null);

  const reportTemplates: ReportTemplate[] = [
    {
      id: 'executive-summary',
      name: 'Executive Security Summary',
      description: 'High-level security overview for C-suite and board members',
      sections: [
        { id: 'risk-overview', title: 'Risk Overview', required: true, order: 1, contentType: 'text', promptTemplate: 'Provide business-focused risk summary' },
        { id: 'business-impact', title: 'Business Impact', required: true, order: 2, contentType: 'table', promptTemplate: 'Analyze business impact of security findings' },
        { id: 'investment', title: 'Investment Recommendations', required: true, order: 3, contentType: 'text', promptTemplate: 'Suggest security investments with ROI' },
        { id: 'compliance', title: 'Compliance Status', required: true, order: 4, contentType: 'chart', promptTemplate: 'Show compliance posture' }
      ],
      format: 'executive',
      customizable: true,
      version: '1.0',
      createdAt: new Date('2025-01-01'),
      updatedAt: new Date('2025-01-01'),
      metadata: {
        estimatedTokens: 2000,
        avgGenerationTime: 45,
        usageCount: 0
      }
    },
    {
      id: 'technical-assessment',
      name: 'Technical Security Assessment',
      description: 'Detailed technical findings for security teams and architects',
      sections: [
        { id: 'vuln-analysis', title: 'Vulnerability Analysis', required: true, order: 1, contentType: 'table', promptTemplate: 'Detail each vulnerability with CVSS scores' },
        { id: 'attack-vectors', title: 'Attack Vectors', required: true, order: 2, contentType: 'text', promptTemplate: 'Explain attack scenarios and vectors' },
        { id: 'remediation', title: 'Remediation Steps', required: true, order: 3, contentType: 'code', promptTemplate: 'Provide step-by-step remediation with code' },
        { id: 'code-examples', title: 'Code Examples', required: false, order: 4, contentType: 'code', promptTemplate: 'Show secure code implementations' }
      ],
      format: 'technical',
      customizable: true,
      version: '1.0',
      createdAt: new Date('2025-01-01'),
      updatedAt: new Date('2025-01-01'),
      metadata: {
        estimatedTokens: 3500,
        avgGenerationTime: 60,
        usageCount: 0
      }
    },
    {
      id: 'compliance-report',
      name: 'Compliance & Risk Report',
      description: 'Regulatory compliance status and risk management',
      sections: [
        { id: 'regulatory', title: 'Regulatory Status', required: true, order: 1, contentType: 'table', promptTemplate: 'Map findings to compliance frameworks' },
        { id: 'risk-matrix', title: 'Risk Matrix', required: true, order: 2, contentType: 'chart', promptTemplate: 'Create risk heat map' },
        { id: 'audit-trail', title: 'Audit Trail', required: true, order: 3, contentType: 'table', promptTemplate: 'Document audit evidence' },
        { id: 'actions', title: 'Action Items', required: true, order: 4, contentType: 'table', promptTemplate: 'List compliance actions needed' }
      ],
      format: 'compliance',
      customizable: true,
      version: '1.0',
      createdAt: new Date('2025-01-01'),
      updatedAt: new Date('2025-01-01'),
      metadata: {
        estimatedTokens: 2800,
        avgGenerationTime: 55,
        usageCount: 0
      }
    },
    {
      id: 'developer-guide',
      name: 'Developer Security Guide',
      description: 'Actionable security guidance for development teams',
      sections: [
        { id: 'code-vulns', title: 'Code Vulnerabilities', required: true, order: 1, contentType: 'code', promptTemplate: 'Show vulnerable code patterns' },
        { id: 'best-practices', title: 'Best Practices', required: true, order: 2, contentType: 'text', promptTemplate: 'List secure coding practices' },
        { id: 'implementation', title: 'Implementation Examples', required: true, order: 3, contentType: 'code', promptTemplate: 'Provide secure implementation examples' },
        { id: 'testing', title: 'Testing Guidelines', required: false, order: 4, contentType: 'text', promptTemplate: 'Explain security testing approaches' }
      ],
      format: 'developer',
      customizable: true,
      version: '1.0',
      createdAt: new Date('2025-01-01'),
      updatedAt: new Date('2025-01-01'),
      metadata: {
        estimatedTokens: 3200,
        avgGenerationTime: 50,
        usageCount: 0
      }
    }
  ];

  const audienceProfiles: AudienceProfile[] = [
    {
      id: 'exec-001',
      type: 'executive',
      name: 'Executive Leadership',
      description: 'C-suite and board members focused on business risk and ROI',
      focusAreas: ['Business risk', 'Compliance status', 'Investment needs', 'Strategic alignment'],
      technicalLevel: 'low',
      preferredFormat: 'summary',
      communicationStyle: 'business',
      priorityMetrics: ['Business risk', 'ROI', 'Compliance score', 'Timeline'],
      excludedTopics: ['Technical implementation details', 'Code-level issues']
    },
    {
      id: 'tech-001',
      type: 'technical',
      name: 'Technical Security Teams',
      description: 'Security engineers and architects needing deep technical details',
      focusAreas: ['Vulnerability analysis', 'Attack vectors', 'Remediation steps', 'Technical debt'],
      technicalLevel: 'high',
      preferredFormat: 'detailed',
      communicationStyle: 'technical',
      priorityMetrics: ['CVSS scores', 'Exploit availability', 'Remediation complexity', 'Detection coverage'],
      excludedTopics: ['Business ROI calculations']
    },
    {
      id: 'comp-001',
      type: 'compliance',
      name: 'Compliance & Audit Teams',
      description: 'Compliance officers and auditors focused on regulatory requirements',
      focusAreas: ['Regulatory compliance', 'Audit evidence', 'Policy violations', 'Risk frameworks'],
      technicalLevel: 'medium',
      preferredFormat: 'reference',
      communicationStyle: 'formal',
      priorityMetrics: ['Compliance percentage', 'Policy violations', 'Control effectiveness', 'Audit readiness'],
      excludedTopics: ['Code implementation details']
    },
    {
      id: 'dev-001',
      type: 'developer',
      name: 'Development Teams',
      description: 'Software developers needing actionable code-level guidance',
      focusAreas: ['Code vulnerabilities', 'Secure patterns', 'Implementation examples', 'Testing strategies'],
      technicalLevel: 'high',
      preferredFormat: 'detailed',
      communicationStyle: 'educational',
      priorityMetrics: ['Code quality', 'Fix complexity', 'Development impact', 'Testing coverage'],
      excludedTopics: ['High-level business metrics']
    }
  ];

  const handleGenerateReport = async () => {
    if (!apiKey && llmConfig.provider !== 'local' && llmConfig.provider !== 'lovable-ai') {
      toast({
        title: "API Key Required",
        description: "Please provide your API key for the selected LLM provider",
        variant: "destructive"
      });
      return;
    }

    // Initialize job
    const job: ReportJob = {
      id: `job-${Date.now()}`,
      status: 'initiated',
      progress: 0,
      currentStep: 'Initializing report generation',
      createdAt: new Date(),
      updatedAt: new Date(),
      metadata: {
        templateId: selectedTemplate,
        audienceId: selectedAudience,
        requestedBy: 'current-user',
        priority: 'normal'
      }
    };

    setCurrentJob(job);
    setIsGenerating(true);
    setGenerationProgress(0);

    try {
      // Step 1: Gather data from codebase
      updateJob(job, 'collecting', 20, 'Gathering security data');
      const reportData = await gatherReportData();

      // Step 2: Research online for relevant security examples
      updateJob(job, 'researching', 40, 'Conducting security research');
      const researchData = await conductOnlineResearch();

      // Step 3: Generate audience-adapted content
      updateJob(job, 'generating', 60, 'Generating audience-adapted content');
      const adaptedContent = await generateAdaptedContent(reportData, researchData);

      // Step 4: Format and finalize report
      updateJob(job, 'formatting', 80, 'Formatting final report');
      const finalReport = await formatReport(adaptedContent);

      updateJob(job, 'completed', 100, 'Report generation complete');
      setGeneratedReport(finalReport);

      toast({
        title: "Report Generated Successfully",
        description: `${reportTemplates.find(t => t.id === selectedTemplate)?.name} ready for review`
      });

    } catch (error) {
      console.error('Report generation failed:', error);
      const errorJob: JobError = {
        code: 'GENERATION_FAILED',
        message: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date(),
        retryable: true
      };
      updateJobError(job, errorJob);
      
      toast({
        title: "Generation Failed",
        description: "Failed to generate report. Please check your configuration.",
        variant: "destructive"
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const updateJob = (job: ReportJob, status: JobStatus, progress: number, step: string) => {
    job.status = status;
    job.progress = progress;
    job.currentStep = step;
    job.updatedAt = new Date();
    if (status === 'completed') {
      job.completedAt = new Date();
    }
    setCurrentJob({...job});
    setGenerationProgress(progress);
  };

  const updateJobError = (job: ReportJob, error: JobError) => {
    job.status = 'failed';
    job.error = error;
    job.updatedAt = new Date();
    setCurrentJob({...job});
  };

  const gatherReportData = async (): Promise<ReportData> => {
    // Generate structured report data for SecurityAssessmentReport component
    const targetOrg = reportTitle.includes('Target:') 
      ? reportTitle.split('Target:')[1]?.trim() || 'Target Organization' 
      : 'Target Organization';
    
    const structuredData = {
      target: targetOrg,
      reportId: `IPS-STC-${targetOrg.substring(0, 4).toUpperCase()}-${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}${String(new Date().getDate()).padStart(2, '0')}-RPT-001`,
      date: new Date().toISOString().split('T')[0],
      riskLevel: (['Low', 'Medium', 'High', 'Critical'][Math.floor(Math.random() * 4)]) as any,
      vulnerabilities: {
        high: Math.floor(Math.random() * 5) + 2,
        medium: Math.floor(Math.random() * 10) + 5,
        low: Math.floor(Math.random() * 15) + 10,
      },
      complianceIssues: [
        'GDPR: SQL Injection and credential leakage risks exposure of personal data. Breach notification obligations may apply.',
        'NIS2: Lack of timely patching for high-risk vulnerabilities breaches mandatory resilience obligations for essential services.',
        'ISO 27001: Missing security controls around session management and secure configuration.',
      ],
      infrastructureFindings: [
        'High-risk vulnerabilities include outdated encryption libraries (OpenSSL 1.0.2 - End of Life)',
        'Apache Struts CVE-2025-1234: Remote code execution vulnerability confirmed by scanner',
        'Weak SSH cipher suites detected on production servers - immediate upgrade required',
        'Multiple unpatched systems identified with known CVEs',
      ],
      webAppFindings: [
        'SQL Injection vulnerability in customer portal login form (CVSS 9.8)',
        'Reflected Cross-Site Scripting (XSS) in search functionality',
        'Missing Content Security Policy (CSP) headers across all endpoints',
        'Insecure session management allowing session fixation attacks',
      ],
      siemFindings: [
        'Distributed SSH brute force attempts detected across multiple servers',
        'Successful logins observed from unusual geolocations tied to leaked credentials',
        'Multiple failed authentication attempts followed by successful login patterns',
        'Anomalous data exfiltration patterns detected during off-hours',
      ],
      threatIntel: {
        leakedCredentials: [
          `admin@${targetOrg.toLowerCase().replace(/\s+/g, '')}.com found in credential dump`,
          `sysadmin@${targetOrg.toLowerCase().replace(/\s+/g, '')}.com exposed in underground forum`,
        ],
        suspiciousIPs: [
          '203.0.113.45',
          '198.51.100.23',
          '192.0.2.100',
        ],
        bruteForceAttempts: Math.floor(Math.random() * 500) + 200,
      },
      mitreMapping: [
        {
          tactic: 'Initial Access',
          technique: 'T1078',
          description: 'Valid Accounts used with leaked credentials to gain unauthorized access',
        },
        {
          tactic: 'Credential Access',
          technique: 'T1110',
          description: 'Brute force attacks observed on SSH services targeting administrative accounts',
        },
        {
          tactic: 'Persistence',
          technique: 'T1078',
          description: 'Risk of sustained access if compromised accounts are not rotated',
        },
        {
          tactic: 'Lateral Movement',
          technique: 'T1021.004',
          description: 'SSH could be used to propagate compromise internally across the network',
        },
      ],
      remediationPlan: {
        immediate: [
          'Patch Apache Struts and OpenSSL vulnerabilities immediately',
          'Reset all affected credentials and enforce MFA organization-wide',
          'Fix SQL Injection and XSS vulnerabilities in customer portals',
          'Block identified malicious IP addresses at firewall level',
        ],
        nearTerm: [
          'Enforce strong SSH cipher standards across all servers',
          'Deploy CSP headers and secure session controls in applications',
          'Enhance SIEM detection thresholds for brute force and credential stuffing',
          'Conduct security awareness training for all staff members',
        ],
        longTerm: [
          'Establish continuous vulnerability management program',
          'Conduct red/blue team exercises simulating attack scenarios',
          'Integrate external OSINT feeds into SIEM for proactive detection',
          'Implement zero-trust architecture principles across infrastructure',
        ],
      },
    };
    
    setReportData(structuredData);
    
    // In production, this would integrate with your actual security services
    const now = new Date();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    return {
      vulnerabilities: [
        {
          id: 'vuln-001',
          cveId: 'CVE-2024-0001',
          title: 'SQL Injection in User Authentication',
          description: 'Unvalidated user input in login endpoint allows SQL injection attacks',
          severity: 'Critical',
          cvssScore: 9.8,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          affectedSystems: ['web-app', 'api-gateway'],
          discoveredAt: new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000),
          status: 'Open',
          attackVector: 'Network',
          exploitability: 'Functional',
          cwe: 'CWE-89',
          regulatoryImpact: ['PCI-DSS', 'GDPR'],
          businessImpact: 'Data breach risk, potential compliance fines',
          remediationSteps: ['Implement parameterized queries', 'Add input validation', 'Deploy WAF rules'],
          fixComplexity: 'Medium',
          codeLocation: 'src/auth/login.ts:45'
        }
      ],
      scanResults: [
        {
          id: 'scan-001',
          scanType: 'OWASP',
          timestamp: now,
          status: 'Completed',
          findings: 15,
          breakdown: { critical: 3, high: 7, medium: 5, low: 0, info: 0 },
          coverage: 85,
          duration: 1200,
          targetInfo: { name: 'Web Application', type: 'Application', location: 'https://app.example.com' }
        }
      ],
      complianceStatus: [
        {
          id: 'comp-001',
          framework: 'SOC2 Type II',
          requirement: 'Access Control - CC6.1',
          status: 'Partial',
          score: 75,
          gaps: ['MFA not enforced', 'Insufficient session management'],
          evidence: ['Access logs', 'Configuration files'],
          lastChecked: now,
          nextReview: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000),
          owner: 'Security Team'
        }
      ],
      metrics: {
        riskScore: 7.2,
        riskTrend: 'degrading',
        vulnerabilityBreakdown: { critical: 8, high: 15, medium: 22, low: 10 },
        complianceScore: 78,
        meanTimeToRemediate: 12.5,
        openVulnerabilities: 45,
        resolvedThisPeriod: 8,
        securityPosture: 'fair'
      },
      trends: [
        {
          period: '2025-W01',
          vulnerabilities: 42,
          remediationRate: 65,
          newThreats: 12,
          complianceScore: 75
        }
      ],
      recommendations: [
        {
          id: 'rec-001',
          priority: 'Critical',
          category: 'Access Control',
          title: 'Implement Multi-Factor Authentication',
          description: 'Deploy MFA across all user-facing applications to prevent credential-based attacks',
          impact: 'Reduces account takeover risk by 99.9%',
          effort: 'Medium',
          timeline: '2-4 weeks',
          dependencies: ['Identity Provider integration'],
          resources: ['Security Engineer', 'DevOps Team'],
          successCriteria: ['100% MFA enrollment', 'Zero password-only logins']
        }
      ],
      timeRange: {
        start: weekAgo,
        end: now,
        description: 'Last 7 days'
      },
      dataSourceMetadata: [
        {
          source: 'Wazuh SIEM',
          lastSync: now,
          status: 'active',
          recordCount: 15420,
          quality: 95
        },
        {
          source: 'GVM Scanner',
          lastSync: now,
          status: 'active',
          recordCount: 1250,
          quality: 92
        }
      ]
    };
  };

  const conductOnlineResearch = async () => {
    if (!researchQuery.trim()) return [];

    try {
      // Use Perplexity for online research
      const response = await fetch('https://api.perplexity.ai/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'llama-3.1-sonar-small-128k-online',
          messages: [
            {
              role: 'system',
              content: 'You are a cybersecurity research assistant. Provide current, accurate information about security vulnerabilities, best practices, and code examples.'
            },
            {
              role: 'user',
              content: `Research the latest information about: ${researchQuery}. Include code examples, best practices, and recent developments.`
            }
          ],
          temperature: 0.2,
          max_tokens: 1000,
          return_images: false,
          return_related_questions: false,
          search_recency_filter: 'month'
        }),
      });

      const data = await response.json();
      return data.choices?.[0]?.message?.content || '';
    } catch (error) {
      console.error('Research failed:', error);
      return 'Unable to conduct online research at this time.';
    }
  };

  const generateAdaptedContent = async (reportData: ReportData, researchData: any) => {
    const selectedProfile = audienceProfiles.find(p => p.type === selectedAudience);
    const template = reportTemplates.find(t => t.id === selectedTemplate);

    try {
      let content = '';
      
      if (llmConfig.provider === 'openai') {
        const openaiService = createOpenAIService(apiKey);
        content = await openaiService.generateSecurityReport(
          reportData,
          selectedProfile?.name || 'Technical Teams',
          template?.name || 'Security Assessment',
          customPrompt
        );
        
        // Enhance with research if available
        if (researchData && typeof researchData === 'string') {
          content = await openaiService.enhanceWithResearch(content, researchData);
        }
      } else if (llmConfig.provider === 'perplexity') {
        const systemPrompt = `You are an expert security report writer. Generate a comprehensive security report adapted for ${selectedProfile?.name} with the following characteristics:
        
        Communication Style: ${selectedProfile?.communicationStyle}
        Key Focus Areas: ${selectedProfile?.priorityMetrics.join(', ')}
        Preferred Format: ${selectedProfile?.preferredFormat}
        Technical Level: ${selectedProfile?.technicalLevel}
        
        Report Template: ${template?.name}
        Sections to Include: ${template?.sections.map(s => s.title).join(', ')}
        
        Use the provided security data and online research to create content that resonates with this specific audience.
        ${customPrompt ? `Additional Instructions: ${customPrompt}` : ''}`;

        const userPrompt = `Generate a ${template?.name} based on this security data:
        
        Vulnerabilities: ${JSON.stringify(reportData.vulnerabilities, null, 2)}
        Scan Results: ${JSON.stringify(reportData.scanResults, null, 2)}
        Compliance Status: ${JSON.stringify(reportData.complianceStatus, null, 2)}
        Key Metrics: ${JSON.stringify(reportData.metrics, null, 2)}
        
        Recent Research: ${researchData}
        
        Make sure to include relevant code examples and best practices appropriate for the ${selectedAudience} audience.`;

        const response = await fetch('https://api.perplexity.ai/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: llmConfig.model,
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: userPrompt }
            ],
            temperature: llmConfig.temperature,
            max_tokens: llmConfig.maxTokens
          })
        });

        const data = await response.json();
        content = data?.choices?.[0]?.message?.content || 'Failed to generate content';
      } else {
        // Local model fallback
        content = generateMockReport(reportData, selectedProfile, template);
      }

      return content;
    } catch (error) {
      console.error('Content generation failed:', error);
      throw error;
    }
  };

  const generateMockReport = (reportData: ReportData, profile: any, template: any) => {
    const totalVulns = reportData.metrics.openVulnerabilities;
    const criticalVulns = reportData.metrics.vulnerabilityBreakdown.critical;
    
    return `# ${template?.name || 'Security Assessment Report'}

## Executive Summary
This report provides a comprehensive security assessment tailored for ${profile?.name}. 

## Key Findings
- ${totalVulns} total vulnerabilities identified
- ${criticalVulns} critical issues requiring immediate attention
- Overall compliance score: ${reportData.metrics.complianceScore}%
- Security posture: ${reportData.metrics.securityPosture}

## Recommendations
Based on our analysis, we recommend the following priority actions:

1. **Critical Vulnerabilities**: Address ${criticalVulns} critical security issues
2. **Compliance Gaps**: Improve compliance score from ${reportData.metrics.complianceScore}% to 95%+
3. **Risk Mitigation**: Implement comprehensive security monitoring

## Detailed Analysis
[Detailed technical analysis would be generated here based on the actual data and audience preferences]

## Next Steps
1. Prioritize critical vulnerability remediation
2. Implement recommended security controls
3. Schedule follow-up assessment in 30 days

---
*Report generated using AI-powered audience adaptation technology*`;
  };

  const formatReport = async (content: string) => {
    const timestamp = new Date().toISOString().split('T')[0];
    const audience = audienceProfiles.find(p => p.type === selectedAudience);
    
    return `# ${reportTitle}
**Generated for:** ${audience?.name}
**Date:** ${timestamp}
**Report Type:** ${reportTemplates.find(t => t.id === selectedTemplate)?.name}

---

${content}

---

*This report was generated using AI-powered audience adaptation and includes the latest security research and best practices.*`;
  };

  const handleResearch = async () => {
    if (!researchQuery.trim() || !apiKey) return;

    try {
      const results = await conductOnlineResearch();
      setResearchResults([{
        query: researchQuery,
        results: results,
        timestamp: new Date().toISOString()
      }]);

      toast({
        title: "Research Complete",
        description: "Latest security information retrieved successfully"
      });
    } catch (error) {
      toast({
        title: "Research Failed",
        description: "Unable to conduct online research",
        variant: "destructive"
      });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Intelligent Reporting System</h2>
          <p className="text-muted-foreground">
            AI-powered security reports adapted for your target audience
          </p>
        </div>
        <Badge variant="outline" className="text-sm">
          <Brain className="w-4 h-4 mr-1" />
          AI-Enhanced
        </Badge>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="examples" className="flex items-center gap-2">
            <BookOpen className="w-4 h-4" />
            Examples
          </TabsTrigger>
          <TabsTrigger value="generator" className="flex items-center gap-2">
            <FileText className="w-4 h-4" />
            Generator
          </TabsTrigger>
          <TabsTrigger value="audience" className="flex items-center gap-2">
            <Users className="w-4 h-4" />
            Audience
          </TabsTrigger>
          <TabsTrigger value="research" className="flex items-center gap-2">
            <Search className="w-4 h-4" />
            Research
          </TabsTrigger>
          <TabsTrigger value="settings" className="flex items-center gap-2">
            <Settings className="w-4 h-4" />
            Settings
          </TabsTrigger>
        </TabsList>

        <TabsContent value="examples" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <BookOpen className="w-5 h-5" />
                Example Reports
              </CardTitle>
              <CardDescription>
                Preview different report styles to help you choose the right template and audience
              </CardDescription>
            </CardHeader>
          </Card>

          <div className="grid gap-4">
            {/* Executive Summary - Executive Audience */}
            <Card className="border-primary/20">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle className="text-lg">Executive Security Summary</CardTitle>
                    <CardDescription>For C-Suite & Board Members</CardDescription>
                  </div>
                  <Badge variant="default">Executive</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-72 w-full border rounded-md p-4 bg-muted/30">
                  <div className="space-y-4 text-sm">
                    <div>
                      <h3 className="font-semibold text-base mb-2">📊 Risk Overview</h3>
                      <p className="text-muted-foreground">
                        Our current security posture indicates a <strong>moderate risk level</strong> with 3 critical vulnerabilities requiring immediate attention. Overall risk score: <strong>67/100</strong> (Fair). The primary concerns are outdated SSL certificates affecting customer trust and unpatched systems exposing sensitive data.
                      </p>
                    </div>
                    <Separator />
                    <div>
                      <h3 className="font-semibold text-base mb-2">💼 Business Impact</h3>
                      <div className="bg-background border rounded-md p-3 space-y-2">
                        <div className="flex justify-between">
                          <span>Potential Revenue Loss:</span>
                          <span className="font-medium text-destructive">$500K - $2M</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Regulatory Compliance:</span>
                          <span className="font-medium text-yellow-600">78% (Partial)</span>
                        </div>
                        <div className="flex justify-between">
                          <span>Customer Trust Impact:</span>
                          <span className="font-medium text-destructive">High Risk</span>
                        </div>
                      </div>
                    </div>
                    <Separator />
                    <div>
                      <h3 className="font-semibold text-base mb-2">💰 Investment Recommendations</h3>
                      <ul className="space-y-2 text-muted-foreground">
                        <li>• <strong>$50K:</strong> Immediate vulnerability remediation (ROI: 400% risk reduction)</li>
                        <li>• <strong>$120K:</strong> Security automation platform (ROI: 60% operational efficiency)</li>
                        <li>• <strong>$30K:</strong> Staff security training (ROI: 70% incident reduction)</li>
                      </ul>
                    </div>
                  </div>
                </ScrollArea>
                <div className="flex gap-2 mt-3">
                  <Button size="sm" variant="outline" onClick={() => {
                    setSelectedTemplate('executive-summary');
                    setSelectedAudience('executive');
                    setActiveTab('generator');
                  }}>
                    Use This Template
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Technical Assessment - Technical Audience */}
            <Card className="border-blue-500/20">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle className="text-lg">Technical Security Assessment</CardTitle>
                    <CardDescription>For Security Engineers & DevOps</CardDescription>
                  </div>
                  <Badge variant="secondary">Technical</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-72 w-full border rounded-md p-4 bg-muted/30">
                  <div className="space-y-4 text-sm font-mono">
                    <div>
                      <h3 className="font-semibold text-base mb-2 font-sans">🔍 Vulnerability Analysis</h3>
                      <div className="bg-background border rounded-md p-3 space-y-2">
                        <div>
                          <span className="text-destructive font-bold">[CRITICAL]</span> CVE-2024-1234: SQL Injection in /api/users endpoint
                        </div>
                        <div className="pl-4 text-muted-foreground">
                          CVSS: 9.8 | Attack Vector: Network | Exploitability: High
                          <br />
                          Affected: api-server v2.3.1, Lines 145-167 in user_controller.py
                          <br />
                          Recommendation: Implement parameterized queries, upgrade to v2.3.2
                        </div>
                      </div>
                      <div className="bg-background border rounded-md p-3 mt-2 space-y-2">
                        <div>
                          <span className="text-orange-600 font-bold">[HIGH]</span> CVE-2024-5678: XSS in dashboard component
                        </div>
                        <div className="pl-4 text-muted-foreground">
                          CVSS: 7.4 | CWE-79 | Stored XSS
                          <br />
                          Fix: Sanitize user input in dashboard.tsx:89-102
                        </div>
                      </div>
                    </div>
                    <Separator />
                    <div>
                      <h3 className="font-semibold text-base mb-2 font-sans">🛠️ Technical Recommendations</h3>
                      <ul className="space-y-1 text-muted-foreground">
                        <li>1. Deploy WAF rules for SQL injection protection</li>
                        <li>2. Enable CSP headers: default-src 'self'; script-src 'self'</li>
                        <li>3. Implement rate limiting: 100 req/min per IP</li>
                        <li>4. Update dependencies: express@4.18.2 → 4.19.0</li>
                      </ul>
                    </div>
                  </div>
                </ScrollArea>
                <div className="flex gap-2 mt-3">
                  <Button size="sm" variant="outline" onClick={() => {
                    setSelectedTemplate('technical-assessment');
                    setSelectedAudience('technical');
                    setActiveTab('generator');
                  }}>
                    Use This Template
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Compliance Report - Compliance Audience */}
            <Card className="border-green-500/20">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle className="text-lg">Compliance & Regulatory Report</CardTitle>
                    <CardDescription>For Compliance Officers & Auditors</CardDescription>
                  </div>
                  <Badge className="bg-green-600">Compliance</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-72 w-full border rounded-md p-4 bg-muted/30">
                  <div className="space-y-4 text-sm">
                    <div>
                      <h3 className="font-semibold text-base mb-2">📋 Compliance Status Overview</h3>
                      <div className="space-y-3">
                        <div className="bg-background border rounded-md p-3">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-medium">SOC 2 Type II</span>
                            <Badge variant="default" className="bg-green-600">Compliant</Badge>
                          </div>
                          <Progress value={95} className="h-2" />
                          <p className="text-xs text-muted-foreground mt-1">95% - All critical controls met, 2 minor gaps</p>
                        </div>
                        <div className="bg-background border rounded-md p-3">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-medium">GDPR</span>
                            <Badge variant="default" className="bg-yellow-600">Partial</Badge>
                          </div>
                          <Progress value={78} className="h-2" />
                          <p className="text-xs text-muted-foreground mt-1">78% - Data retention policies need updating</p>
                        </div>
                        <div className="bg-background border rounded-md p-3">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-medium">ISO 27001</span>
                            <Badge variant="default" className="bg-green-600">Compliant</Badge>
                          </div>
                          <Progress value={92} className="h-2" />
                          <p className="text-xs text-muted-foreground mt-1">92% - Certified, next audit in 4 months</p>
                        </div>
                      </div>
                    </div>
                    <Separator />
                    <div>
                      <h3 className="font-semibold text-base mb-2">⚠️ Compliance Gaps</h3>
                      <ul className="space-y-2 text-muted-foreground">
                        <li>• <strong>GDPR Art. 30:</strong> Records of processing activities incomplete for 3 systems</li>
                        <li>• <strong>SOC 2 CC6.1:</strong> Logical access controls need documentation update</li>
                        <li>• <strong>PCI-DSS 6.5.1:</strong> Injection flaws identified in payment processing</li>
                      </ul>
                    </div>
                    <Separator />
                    <div>
                      <h3 className="font-semibold text-base mb-2">✅ Remediation Actions</h3>
                      <ul className="space-y-1 text-muted-foreground text-xs">
                        <li>□ Update data processing records (Due: 30 days, Owner: DPO)</li>
                        <li>□ Document access control procedures (Due: 15 days, Owner: InfoSec)</li>
                        <li>□ Remediate injection vulnerabilities (Due: 7 days, Owner: DevOps)</li>
                      </ul>
                    </div>
                  </div>
                </ScrollArea>
                <div className="flex gap-2 mt-3">
                  <Button size="sm" variant="outline" onClick={() => {
                    setSelectedTemplate('compliance-report');
                    setSelectedAudience('compliance');
                    setActiveTab('generator');
                  }}>
                    Use This Template
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Developer Guide - Developer Audience */}
            <Card className="border-purple-500/20">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle className="text-lg">Developer Security Guide</CardTitle>
                    <CardDescription>For Software Developers & Engineering Teams</CardDescription>
                  </div>
                  <Badge className="bg-purple-600">Developer</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-72 w-full border rounded-md p-4 bg-muted/30">
                  <div className="space-y-4 text-sm">
                    <div>
                      <h3 className="font-semibold text-base mb-2">🐛 Code-Level Vulnerabilities</h3>
                      <div className="bg-background border rounded-md p-3 font-mono text-xs">
                        <div className="text-destructive font-bold mb-1">src/api/user.ts:145-167</div>
                        <pre className="text-muted-foreground overflow-x-auto">{`// ❌ VULNERABLE CODE
const query = \`SELECT * FROM users 
  WHERE email = '\${email}'\`;
db.execute(query);

// ✅ FIXED CODE  
const query = 'SELECT * FROM users WHERE email = ?';
db.execute(query, [email]);`}</pre>
                      </div>
                    </div>
                    <Separator />
                    <div>
                      <h3 className="font-semibold text-base mb-2">🔧 Quick Fixes</h3>
                      <div className="space-y-2">
                        <div className="bg-background border rounded-md p-3">
                          <div className="font-medium mb-1">1. Update Dependencies</div>
                          <code className="text-xs bg-muted p-2 rounded block">npm audit fix && npm update express helmet cors</code>
                        </div>
                        <div className="bg-background border rounded-md p-3">
                          <div className="font-medium mb-1">2. Enable Security Headers</div>
                          <code className="text-xs bg-muted p-2 rounded block">app.use(helmet()); // Add to server.ts</code>
                        </div>
                        <div className="bg-background border rounded-md p-3">
                          <div className="font-medium mb-1">3. Add Input Validation</div>
                          <code className="text-xs bg-muted p-2 rounded block">{`import { z } from 'zod';`}</code>
                        </div>
                      </div>
                    </div>
                    <Separator />
                    <div>
                      <h3 className="font-semibold text-base mb-2">📚 Security Best Practices</h3>
                      <ul className="space-y-1 text-muted-foreground text-xs">
                        <li>✓ Use parameterized queries for all database operations</li>
                        <li>✓ Sanitize user input with validator libraries (zod, joi)</li>
                        <li>✓ Implement CSRF tokens for state-changing operations</li>
                        <li>✓ Enable CORS with strict origin whitelist</li>
                        <li>✓ Use environment variables for secrets (never hardcode)</li>
                      </ul>
                    </div>
                  </div>
                </ScrollArea>
                <div className="flex gap-2 mt-3">
                  <Button size="sm" variant="outline" onClick={() => {
                    setSelectedTemplate('developer-guide');
                    setSelectedAudience('developer');
                    setActiveTab('generator');
                  }}>
                    Use This Template
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Full Executive Report Preview */}
            <Card className="border-primary/30">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <CardTitle className="text-lg">Full Security Assessment Report - Executive Format</CardTitle>
                    <CardDescription>Complete IPS-STC report for Executive Leadership</CardDescription>
                    <div className="flex flex-wrap gap-2 mt-2">
                      <Badge variant="default">Executive Leadership</Badge>
                      <Badge variant="outline">Communication Style: Business</Badge>
                      <Badge variant="outline">Format: Summary</Badge>
                      <Badge variant="outline">Technical Level: Low</Badge>
                    </div>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4 mb-4">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="bg-muted/50 p-3 rounded-lg">
                      <div className="text-xs text-muted-foreground mb-1">Focus Areas</div>
                      <ul className="text-xs space-y-0.5">
                        <li>• Business risk</li>
                        <li>• Compliance status</li>
                        <li>• Investment needs</li>
                        <li>• Strategic alignment</li>
                      </ul>
                    </div>
                    <div className="bg-muted/50 p-3 rounded-lg">
                      <div className="text-xs text-muted-foreground mb-1">Communication Style</div>
                      <div className="text-sm font-medium">Business</div>
                    </div>
                    <div className="bg-muted/50 p-3 rounded-lg">
                      <div className="text-xs text-muted-foreground mb-1">Preferred Format</div>
                      <div className="text-sm font-medium">Summary</div>
                    </div>
                    <div className="bg-muted/50 p-3 rounded-lg">
                      <div className="text-xs text-muted-foreground mb-1">Priority Metrics</div>
                      <ul className="text-xs space-y-0.5">
                        <li>• Business risk</li>
                        <li>• ROI</li>
                        <li>• Compliance score</li>
                        <li>• Timeline</li>
                      </ul>
                    </div>
                  </div>
                </div>

                <ScrollArea className="h-[600px] w-full border rounded-md">
                  <SecurityAssessmentReport 
                    data={{
                      target: 'Example Corporation',
                      reportId: 'IPS-STC-EXAM-2025-1002-RPT-001',
                      date: new Date().toISOString().split('T')[0],
                      riskLevel: 'Medium',
                      vulnerabilities: {
                        high: 4,
                        medium: 8,
                        low: 12,
                      },
                      complianceIssues: [
                        'GDPR: SQL Injection and credential leakage risks exposure of personal data. Breach notification obligations may apply.',
                        'NIS2: Lack of timely patching for high-risk vulnerabilities breaches mandatory resilience obligations for essential services.',
                        'ISO 27001: Missing security controls around session management and secure configuration.',
                      ],
                      infrastructureFindings: [
                        'High-risk vulnerabilities include outdated encryption libraries (OpenSSL 1.0.2 - End of Life)',
                        'Apache Struts CVE-2025-1234: Remote code execution vulnerability confirmed',
                        'Weak SSH cipher suites detected on production servers',
                      ],
                      webAppFindings: [
                        'SQL Injection vulnerability in customer portal login form',
                        'Reflected Cross-Site Scripting (XSS) in search functionality',
                        'Missing Content Security Policy (CSP) headers',
                      ],
                      siemFindings: [
                        'Distributed SSH brute force attempts detected across multiple servers',
                        'Successful logins from unusual geolocations tied to leaked credentials',
                        'Multiple failed authentication attempts followed by successful login',
                      ],
                      threatIntel: {
                        leakedCredentials: [
                          'admin@examplecorp.com found in credential dump',
                          'sysadmin@examplecorp.com exposed in underground forum',
                        ],
                        suspiciousIPs: [
                          '203.0.113.45',
                          '198.51.100.23',
                          '192.0.2.100',
                        ],
                        bruteForceAttempts: 324,
                      },
                      mitreMapping: [
                        {
                          tactic: 'Initial Access',
                          technique: 'T1078',
                          description: 'Valid Accounts used with leaked credentials',
                        },
                        {
                          tactic: 'Credential Access',
                          technique: 'T1110',
                          description: 'Brute force observed on SSH services',
                        },
                        {
                          tactic: 'Persistence',
                          technique: 'T1078',
                          description: 'Risk of sustained access if compromised accounts are not rotated',
                        },
                        {
                          tactic: 'Lateral Movement',
                          technique: 'T1021.004',
                          description: 'SSH could be used to propagate compromise internally',
                        },
                      ],
                      remediationPlan: {
                        immediate: [
                          'Patch Apache Struts and OpenSSL vulnerabilities immediately',
                          'Reset all affected credentials and enforce MFA organization-wide',
                          'Fix SQL Injection and XSS vulnerabilities in customer portals',
                          'Block identified malicious IP addresses at firewall level',
                        ],
                        nearTerm: [
                          'Enforce strong SSH cipher standards across all servers',
                          'Deploy CSP headers and secure session controls in applications',
                          'Enhance SIEM detection thresholds for brute force and credential stuffing',
                          'Conduct security awareness training for all staff',
                        ],
                        longTerm: [
                          'Establish continuous vulnerability management program',
                          'Conduct red/blue team exercises simulating attack scenarios',
                          'Integrate external OSINT feeds into SIEM for proactive detection',
                          'Implement zero-trust architecture principles',
                        ],
                      },
                    }}
                    audienceType="executive"
                  />
                </ScrollArea>
                <div className="flex gap-2 mt-3">
                  <Button size="sm" variant="outline" onClick={() => {
                    setSelectedTemplate('executive-summary');
                    setSelectedAudience('executive');
                    setReportTitle('Security Assessment Report - Target: Example Corporation');
                    setActiveTab('generator');
                  }}>
                    Generate Similar Report
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="generator" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Report Configuration</CardTitle>
                <CardDescription>
                  Configure your security report generation
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="report-title">Report Title</Label>
                  <Input
                    id="report-title"
                    value={reportTitle}
                    onChange={(e) => setReportTitle(e.target.value)}
                    placeholder="Security Assessment Report"
                  />
                </div>

                <div>
                  <Label htmlFor="report-source">Report Data Source</Label>
                  <Select value={reportSource} onValueChange={setReportSource}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select data source" />
                    </SelectTrigger>
                    <SelectContent className="bg-popover border z-50">
                      <SelectItem value="wazuh">Wazuh SIEM Logs</SelectItem>
                      <SelectItem value="openvas">OpenVAS/GVM Scans</SelectItem>
                      <SelectItem value="owaspzap">OWASP ZAP Results</SelectItem>
                      <SelectItem value="spiderfoot">SpiderFoot OSINT</SelectItem>
                      <SelectItem value="network">Network Scans</SelectItem>
                      <SelectItem value="webapp">Web Application Tests</SelectItem>
                      <SelectItem value="ad">Active Directory Assessment</SelectItem>
                      <SelectItem value="manual">Manual Input Data</SelectItem>
                      <SelectItem value="combined">All Available Sources</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-sm text-muted-foreground mt-1">
                    Choose the security tool or data source for report generation
                  </p>
                </div>

                <div>
                  <Label htmlFor="template">Report Template</Label>
                  <Select value={selectedTemplate} onValueChange={setSelectedTemplate}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select a template" />
                    </SelectTrigger>
                    <SelectContent>
                      {reportTemplates.map((template) => (
                        <SelectItem key={template.id} value={template.id}>
                          {template.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label htmlFor="audience">Target Audience</Label>
                  <Select value={selectedAudience} onValueChange={setSelectedAudience}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {audienceProfiles.map((profile) => (
                        <SelectItem key={profile.type} value={profile.type}>
                          {profile.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label htmlFor="custom-prompt">Custom Instructions (Optional)</Label>
                  <Textarea
                    id="custom-prompt"
                    value={customPrompt}
                    onChange={(e) => setCustomPrompt(e.target.value)}
                    placeholder="Additional instructions for report generation..."
                    rows={3}
                  />
                </div>

                <Button 
                  onClick={handleGenerateReport} 
                  disabled={isGenerating || !selectedTemplate || !apiKey}
                  className="w-full"
                >
                  {isGenerating ? (
                    <>
                      <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                      Generating...
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4 mr-2" />
                      Generate Intelligent Report
                    </>
                  )}
                </Button>

                {isGenerating && (
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Generation Progress</span>
                      <span>{generationProgress}%</span>
                    </div>
                    <Progress value={generationProgress} />
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Selected Template</CardTitle>
                <CardDescription>
                  Preview of your selected report configuration
                </CardDescription>
              </CardHeader>
              <CardContent>
                {selectedTemplate ? (
                  <div className="space-y-3">
                    <div>
                      <Label className="text-sm font-medium">Template</Label>
                      <p className="text-sm text-muted-foreground">
                        {reportTemplates.find(t => t.id === selectedTemplate)?.name}
                      </p>
                    </div>
                    <div>
                      <Label className="text-sm font-medium">Audience</Label>
                      <p className="text-sm text-muted-foreground">
                        {audienceProfiles.find(p => p.type === selectedAudience)?.name}
                      </p>
                    </div>
                    <div>
                      <Label className="text-sm font-medium">Sections</Label>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {reportTemplates.find(t => t.id === selectedTemplate)?.sections.map((section) => (
                          <Badge key={section.id} variant="secondary" className="text-xs">
                            {section.title}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    Select a template to see the preview
                  </p>
                )}
              </CardContent>
            </Card>
          </div>

          {generatedReport && reportData && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 justify-between">
                  <div className="flex items-center gap-2">
                    <CheckCircle className="w-5 h-5 text-primary" />
                    Generated Report
                  </div>
                  <div className="flex gap-2">
                    <Button 
                      size="sm" 
                      variant="outline"
                      onClick={() => setShowStructuredReport(!showStructuredReport)}
                    >
                      {showStructuredReport ? 'Show Raw' : 'Show Formatted'}
                    </Button>
                    <Button 
                      size="sm" 
                      variant="outline"
                      onClick={() => {
                        const blob = new Blob([generatedReport], { type: 'text/plain' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `${reportTitle.replace(/\s+/g, '_')}_${new Date().toISOString().split('T')[0]}.txt`;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                      }}
                    >
                      <Download className="w-4 h-4 mr-1" />
                      Download
                    </Button>
                  </div>
                </CardTitle>
                <CardDescription>
                  Your AI-generated, audience-adapted security assessment report
                </CardDescription>
              </CardHeader>
              <CardContent>
                {showStructuredReport ? (
                  <SecurityAssessmentReport 
                    data={reportData} 
                    audienceType={selectedAudience as 'executive' | 'technical' | 'compliance'} 
                  />
                ) : (
                  <>
                    <ScrollArea className="h-96 w-full border rounded-md p-4">
                      <pre className="text-sm whitespace-pre-wrap">{generatedReport}</pre>
                    </ScrollArea>
                    <div className="flex gap-2 mt-4">
                      <Button size="sm" variant="outline">
                        <Eye className="w-4 h-4 mr-1" />
                        Preview
                      </Button>
                      <Button size="sm" variant="outline">
                        <Send className="w-4 h-4 mr-1" />
                        Share
                      </Button>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="audience" className="space-y-4">
          <div className="grid gap-4">
            {audienceProfiles.map((profile) => (
              <Card key={profile.type} className={selectedAudience === profile.type ? 'ring-2 ring-primary' : ''}>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Users className="w-5 h-5" />
                    {profile.name}
                    {selectedAudience === profile.type && (
                      <Badge variant="default">Selected</Badge>
                    )}
                  </CardTitle>
                  <CardDescription>
                    Communication Style: {profile.communicationStyle}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                    <div>
                      <Label className="font-medium">Focus Areas</Label>
                      <ul className="mt-1 space-y-1">
                        {profile.focusAreas.map((area: string) => (
                          <li key={area} className="text-muted-foreground">• {area}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <Label className="font-medium">Communication Style</Label>
                      <p className="mt-1 text-muted-foreground capitalize">{profile.communicationStyle}</p>
                      <Label className="font-medium mt-3">Preferred Format</Label>
                      <p className="mt-1 text-muted-foreground capitalize">{profile.preferredFormat}</p>
                      <Label className="font-medium mt-3">Technical Level</Label>
                      <p className="mt-1 text-muted-foreground capitalize">{profile.technicalLevel}</p>
                    </div>
                    <div>
                      <Label className="font-medium">Priority Metrics</Label>
                      <ul className="mt-1 space-y-1">
                        {profile.priorityMetrics.map((metric: string) => (
                          <li key={metric} className="text-muted-foreground">• {metric}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                  <Button 
                    size="sm" 
                    variant={selectedAudience === profile.type ? "default" : "outline"}
                    onClick={() => setSelectedAudience(profile.type)}
                    className="mt-3"
                  >
                    Select Audience
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="research" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Online Security Research</CardTitle>
              <CardDescription>
                Research the latest security information to enhance your reports
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Input
                  value={researchQuery}
                  onChange={(e) => setResearchQuery(e.target.value)}
                  placeholder="e.g., latest OWASP vulnerabilities, container security best practices"
                  className="flex-1"
                />
                <Button onClick={handleResearch} disabled={!apiKey || !researchQuery.trim()}>
                  <Search className="w-4 h-4 mr-1" />
                  Research
                </Button>
              </div>

              {researchResults.length > 0 && (
                <div className="space-y-4">
                  <Label className="text-sm font-medium">Research Results</Label>
                  {researchResults.map((result, index) => (
                    <Card key={index}>
                      <CardHeader>
                        <CardTitle className="text-sm">Query: {result.query}</CardTitle>
                        <CardDescription>
                          {new Date(result.timestamp).toLocaleString()}
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <ScrollArea className="h-48 w-full">
                          <pre className="text-sm whitespace-pre-wrap">{result.results}</pre>
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="settings" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>LLM Configuration</CardTitle>
              <CardDescription>
                Configure your AI model for report generation
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="provider">LLM Provider</Label>
                <Select value={llmConfig.provider} onValueChange={(value: any) => setLlmConfig({...llmConfig, provider: value})}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="openai">OpenAI</SelectItem>
                    <SelectItem value="perplexity">Perplexity</SelectItem>
                    <SelectItem value="local">Local Model</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="model">Model</Label>
                <Select value={llmConfig.model} onValueChange={(value) => setLlmConfig({...llmConfig, model: value})}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {llmConfig.provider === 'openai' && (
                      <>
                        <SelectItem value="gpt-5-2025-08-07">GPT-5 (Recommended)</SelectItem>
                        <SelectItem value="gpt-4.1-2025-04-14">GPT-4.1</SelectItem>
                        <SelectItem value="gpt-5-mini-2025-08-07">GPT-5 Mini</SelectItem>
                      </>
                    )}
                    {llmConfig.provider === 'perplexity' && (
                      <>
                        <SelectItem value="llama-3.1-sonar-large-128k-online">Llama 3.1 Sonar Large</SelectItem>
                        <SelectItem value="llama-3.1-sonar-small-128k-online">Llama 3.1 Sonar Small</SelectItem>
                      </>
                    )}
                  </SelectContent>
                </Select>
              </div>

              {llmConfig.provider !== 'local' && (
                <div>
                  <Label htmlFor="api-key">API Key</Label>
                  <Input
                    id="api-key"
                    type="password"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder="Enter your API key"
                  />
                </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="temperature">Temperature: {llmConfig.temperature}</Label>
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.1"
                    value={llmConfig.temperature}
                    onChange={(e) => setLlmConfig({...llmConfig, temperature: parseFloat(e.target.value)})}
                    className="w-full"
                  />
                </div>
                <div>
                  <Label htmlFor="max-tokens">Max Tokens</Label>
                  <Input
                    type="number"
                    value={llmConfig.maxTokens}
                    onChange={(e) => setLlmConfig({...llmConfig, maxTokens: parseInt(e.target.value)})}
                    min="500"
                    max="8000"
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};