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

interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  audience: 'executive' | 'technical' | 'compliance' | 'developer';
  sections: string[];
  format: 'pdf' | 'html' | 'markdown' | 'presentation';
}

interface AudienceProfile {
  type: 'executive' | 'technical' | 'compliance' | 'developer';
  name: string;
  characteristics: string[];
  preferredFormat: string[];
  keyMetrics: string[];
  communicationStyle: string;
}

interface ReportData {
  vulnerabilities: any[];
  scanResults: any[];
  complianceStatus: any[];
  recommendations: any[];
  metrics: any;
}

interface LLMConfig {
  provider: 'openai' | 'perplexity' | 'local';
  model: string;
  apiKey?: string;
  temperature: number;
  maxTokens: number;
}

export const IntelligentReportingSystem: React.FC = () => {
  const [activeTab, setActiveTab] = useState('generator');
  const [selectedTemplate, setSelectedTemplate] = useState<string>('');
  const [selectedAudience, setSelectedAudience] = useState<string>('technical');
  const [reportTitle, setReportTitle] = useState('Security Assessment Report');
  const [reportSource, setReportSource] = useState<string>('combined');
  const [isGenerating, setIsGenerating] = useState(false);
  const [generationProgress, setGenerationProgress] = useState(0);
  const [generatedReport, setGeneratedReport] = useState<string>('');
  const [researchQuery, setResearchQuery] = useState('');
  const [researchResults, setResearchResults] = useState<any[]>([]);
  
  const [llmConfig, setLlmConfig] = useState<LLMConfig>({
    provider: 'openai',
    model: 'gpt-5-2025-08-07',
    temperature: 0.3,
    maxTokens: 4000
  });

  const [apiKey, setApiKey] = useState('');
  const [customPrompt, setCustomPrompt] = useState('');

  const reportTemplates: ReportTemplate[] = [
    {
      id: 'executive-summary',
      name: 'Executive Security Summary',
      description: 'High-level security overview for C-suite and board members',
      audience: 'executive',
      sections: ['Risk Overview', 'Business Impact', 'Investment Recommendations', 'Compliance Status'],
      format: 'presentation'
    },
    {
      id: 'technical-assessment',
      name: 'Technical Security Assessment',
      description: 'Detailed technical findings for security teams and architects',
      audience: 'technical',
      sections: ['Vulnerability Analysis', 'Attack Vectors', 'Remediation Steps', 'Code Examples'],
      format: 'html'
    },
    {
      id: 'compliance-report',
      name: 'Compliance & Risk Report',
      description: 'Regulatory compliance status and risk management',
      audience: 'compliance',
      sections: ['Regulatory Status', 'Risk Matrix', 'Audit Trail', 'Action Items'],
      format: 'pdf'
    },
    {
      id: 'developer-guide',
      name: 'Developer Security Guide',
      description: 'Actionable security guidance for development teams',
      audience: 'developer',
      sections: ['Code Vulnerabilities', 'Best Practices', 'Implementation Examples', 'Testing Guidelines'],
      format: 'markdown'
    }
  ];

  const audienceProfiles: AudienceProfile[] = [
    {
      type: 'executive',
      name: 'Executive Leadership',
      characteristics: ['Business-focused', 'Risk-aware', 'ROI-oriented', 'Time-constrained'],
      preferredFormat: ['Visual dashboards', 'High-level summaries', 'Risk matrices'],
      keyMetrics: ['Business risk', 'Compliance status', 'Investment needs', 'Timeline'],
      communicationStyle: 'Concise, business-impact focused, strategic recommendations'
    },
    {
      type: 'technical',
      name: 'Technical Teams',
      characteristics: ['Detail-oriented', 'Solution-focused', 'Tool-savvy', 'Implementation-ready'],
      preferredFormat: ['Technical details', 'Code examples', 'Step-by-step guides'],
      keyMetrics: ['Vulnerability details', 'CVSS scores', 'Remediation steps', 'Technical debt'],
      communicationStyle: 'Technical depth, actionable steps, implementation details'
    },
    {
      type: 'compliance',
      name: 'Compliance & Risk',
      characteristics: ['Regulation-focused', 'Audit-ready', 'Process-oriented', 'Documentation-heavy'],
      preferredFormat: ['Compliance matrices', 'Audit trails', 'Policy mappings'],
      keyMetrics: ['Compliance percentage', 'Policy violations', 'Audit findings', 'Risk scores'],
      communicationStyle: 'Formal, regulation-aligned, evidence-based, audit-ready'
    },
    {
      type: 'developer',
      name: 'Development Teams',
      characteristics: ['Code-focused', 'Integration-minded', 'Efficiency-driven', 'Learning-oriented'],
      preferredFormat: ['Code snippets', 'Integration guides', 'Best practices'],
      keyMetrics: ['Code quality', 'Security debt', 'Fix complexity', 'Development impact'],
      communicationStyle: 'Practical, code-heavy, example-driven, learning-focused'
    }
  ];

  const handleGenerateReport = async () => {
    if (!apiKey && llmConfig.provider !== 'local') {
      toast({
        title: "API Key Required",
        description: "Please provide your API key for the selected LLM provider",
        variant: "destructive"
      });
      return;
    }

    setIsGenerating(true);
    setGenerationProgress(0);

    try {
      // Step 1: Gather data from codebase
      setGenerationProgress(20);
      const reportData = await gatherReportData();

      // Step 2: Research online for relevant security examples
      setGenerationProgress(40);
      const researchData = await conductOnlineResearch();

      // Step 3: Generate audience-adapted content
      setGenerationProgress(60);
      const adaptedContent = await generateAdaptedContent(reportData, researchData);

      // Step 4: Format and finalize report
      setGenerationProgress(80);
      const finalReport = await formatReport(adaptedContent);

      setGeneratedReport(finalReport);
      setGenerationProgress(100);

      toast({
        title: "Report Generated Successfully",
        description: "Your intelligent security report is ready for review"
      });

    } catch (error) {
      console.error('Report generation failed:', error);
      toast({
        title: "Generation Failed",
        description: "Failed to generate report. Please check your configuration.",
        variant: "destructive"
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const gatherReportData = async (): Promise<ReportData> => {
    // Simulate gathering data from the existing codebase
    // In production, this would integrate with your actual security services
    return {
      vulnerabilities: [
        {
          id: 'CVE-2024-0001',
          severity: 'Critical',
          cvss: 9.8,
          description: 'Remote Code Execution vulnerability',
          affectedSystems: ['web-app', 'api-gateway'],
          status: 'open'
        }
      ],
      scanResults: [
        {
          type: 'OWASP',
          findings: 15,
          critical: 3,
          high: 7,
          medium: 5
        }
      ],
      complianceStatus: [
        {
          framework: 'SOC2',
          status: 85,
          gaps: ['Access controls', 'Monitoring']
        }
      ],
      recommendations: [
        {
          priority: 'High',
          category: 'Access Control',
          description: 'Implement multi-factor authentication'
        }
      ],
      metrics: {
        totalVulnerabilities: 45,
        criticalVulnerabilities: 8,
        complianceScore: 85,
        riskScore: 7.2
      }
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
        Key Focus Areas: ${selectedProfile?.keyMetrics.join(', ')}
        Preferred Formats: ${selectedProfile?.preferredFormat.join(', ')}
        
        Report Template: ${template?.name}
        Sections to Include: ${template?.sections.join(', ')}
        
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
    return `# ${template?.name || 'Security Assessment Report'}

## Executive Summary
This report provides a comprehensive security assessment tailored for ${profile?.name}. 

## Key Findings
- ${reportData.metrics.totalVulnerabilities} total vulnerabilities identified
- ${reportData.metrics.criticalVulnerabilities} critical issues requiring immediate attention
- Overall compliance score: ${reportData.metrics.complianceScore}%

## Recommendations
Based on our analysis, we recommend the following priority actions:

1. **Critical Vulnerabilities**: Address ${reportData.metrics.criticalVulnerabilities} critical security issues
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
        <TabsList className="grid w-full grid-cols-4">
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
                          <Badge key={section} variant="secondary" className="text-xs">
                            {section}
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

          {generatedReport && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <CheckCircle className="w-5 h-5 text-primary" />
                  Generated Report
                </CardTitle>
                <CardDescription>
                  Your AI-generated, audience-adapted security report
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-96 w-full border rounded-md p-4">
                  <pre className="text-sm whitespace-pre-wrap">{generatedReport}</pre>
                </ScrollArea>
                <div className="flex gap-2 mt-4">
                  <Button size="sm" variant="outline">
                    <Download className="w-4 h-4 mr-1" />
                    Download PDF
                  </Button>
                  <Button size="sm" variant="outline">
                    <Eye className="w-4 h-4 mr-1" />
                    Preview
                  </Button>
                  <Button size="sm" variant="outline">
                    <Send className="w-4 h-4 mr-1" />
                    Share
                  </Button>
                </div>
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
                      <Label className="font-medium">Characteristics</Label>
                      <ul className="mt-1 space-y-1">
                        {profile.characteristics.map((char) => (
                          <li key={char} className="text-muted-foreground">• {char}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <Label className="font-medium">Preferred Formats</Label>
                      <ul className="mt-1 space-y-1">
                        {profile.preferredFormat.map((format) => (
                          <li key={format} className="text-muted-foreground">• {format}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <Label className="font-medium">Key Metrics</Label>
                      <ul className="mt-1 space-y-1">
                        {profile.keyMetrics.map((metric) => (
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