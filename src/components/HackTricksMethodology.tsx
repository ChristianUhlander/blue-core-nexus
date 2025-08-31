/**
 * HackTricks Methodology Implementation
 * Integration with HackTricks penetration testing methodology and knowledge base
 * 
 * Features:
 * - Real-time HackTricks content integration
 * - AI-powered technique recommendations
 * - Perplexity research integration
 * - Structured attack methodology
 * - MITRE ATT&CK mapping
 * - Custom technique library
 */

import React, { useState, useCallback, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { 
  BookOpen, 
  Search, 
  Target, 
  Zap,
  Brain,
  PlayCircle,
  StopCircle,
  Eye,
  Terminal,
  Activity,
  Clock,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Download,
  ExternalLink,
  Loader2,
  Settings,
  Lock,
  Unlock,
  Server,
  Globe,
  Bug,
  Lightbulb,
  FileText,
  ArrowRight,
  Shield,
  Code,
  Database,
  Network
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { modernPentestApi } from "@/services/modernPentestApi";
import { 
  HackTricksPhase, 
  HackTricksTechnique, 
  TechniqueCommand 
} from "@/types/modernPentest";

interface HackTricksMethodologyProps {
  sessionId?: string;
  targetType: string;
}

interface HackTricksQuery {
  id: string;
  query: string;
  timestamp: string;
  answer: string;
  sources: string[];
  relatedTechniques: string[];
}

export const HackTricksMethodology: React.FC<HackTricksMethodologyProps> = ({ 
  sessionId, 
  targetType 
}) => {
  const { toast } = useToast();

  // HackTricks state
  const [phases, setPhases] = useState<HackTricksPhase[]>([]);
  const [currentPhase, setCurrentPhase] = useState<HackTricksPhase | null>(null);
  const [techniques, setTechniques] = useState<HackTricksTechnique[]>([]);
  const [selectedTechnique, setSelectedTechnique] = useState<HackTricksTechnique | null>(null);
  
  // Research state
  const [researchQuery, setResearchQuery] = useState('');
  const [researchResults, setResearchResults] = useState<HackTricksQuery[]>([]);
  const [isResearching, setIsResearching] = useState(false);

  // Execution state
  const [executingTechnique, setExecutingTechnique] = useState<string | null>(null);
  const [executionHistory, setExecutionHistory] = useState<any[]>([]);

  // Mock HackTricks phases for different target types
  const mockPhases: Record<string, HackTricksPhase[]> = {
    kubernetes: [
      {
        id: 'k8s-recon',
        name: 'Kubernetes Reconnaissance',
        description: 'Discover and enumerate Kubernetes cluster components',
        techniques: [],
        prerequisites: ['Network access to cluster'],
        expectedOutputs: ['Service discovery', 'Version information', 'Exposed endpoints'],
        successCriteria: ['Cluster endpoints identified', 'API server accessible', 'Service enumeration complete']
      },
      {
        id: 'k8s-enum',
        name: 'Kubernetes Enumeration',
        description: 'Deep enumeration of cluster configuration and security',
        techniques: [],
        prerequisites: ['Basic cluster access'],
        expectedOutputs: ['RBAC configuration', 'Pod security policies', 'Network policies'],
        successCriteria: ['RBAC mapped', 'Security contexts identified', 'Service accounts enumerated']
      },
      {
        id: 'k8s-exploit',
        name: 'Kubernetes Exploitation',
        description: 'Exploit identified vulnerabilities and misconfigurations',
        techniques: [],
        prerequisites: ['Enumeration complete'],
        expectedOutputs: ['Container escape', 'Privilege escalation', 'Lateral movement'],
        successCriteria: ['Host access achieved', 'Cluster admin privileges', 'Persistent access']
      }
    ],
    active_directory: [
      {
        id: 'ad-recon',
        name: 'Active Directory Reconnaissance',
        description: 'Initial domain enumeration and information gathering',
        techniques: [],
        prerequisites: ['Domain network access'],
        expectedOutputs: ['Domain structure', 'User enumeration', 'Service discovery'],
        successCriteria: ['Domain controllers identified', 'Trust relationships mapped', 'User accounts discovered']
      },
      {
        id: 'ad-enum',
        name: 'Active Directory Enumeration',
        description: 'Comprehensive AD environment mapping',
        techniques: [],
        prerequisites: ['Domain credentials or access'],
        expectedOutputs: ['BloodHound data', 'GPO analysis', 'Privilege mapping'],
        successCriteria: ['Attack paths identified', 'High-value targets found', 'Delegation relationships mapped']
      },
      {
        id: 'ad-exploit',
        name: 'Active Directory Exploitation',
        description: 'Execute attacks against identified targets',
        techniques: [],
        prerequisites: ['Target identification complete'],
        expectedOutputs: ['Credential theft', 'Lateral movement', 'Persistence'],
        successCriteria: ['Domain admin privileges', 'Golden ticket created', 'Persistent backdoor']
      }
    ],
    web_application: [
      {
        id: 'web-recon',
        name: 'Web Application Reconnaissance',
        description: 'Information gathering and attack surface mapping',
        techniques: [],
        prerequisites: ['Target URL accessible'],
        expectedOutputs: ['Technology stack', 'Directory enumeration', 'Parameter discovery'],
        successCriteria: ['Framework identified', 'Admin panels found', 'Input vectors mapped']
      },
      {
        id: 'web-vuln',
        name: 'Vulnerability Assessment',
        description: 'Identify and validate security vulnerabilities',
        techniques: [],
        prerequisites: ['Reconnaissance complete'],
        expectedOutputs: ['SQLi vulnerabilities', 'XSS vectors', 'Authentication flaws'],
        successCriteria: ['Critical vulnerabilities confirmed', 'Exploitation paths validated', 'Impact assessed']
      },
      {
        id: 'web-exploit',
        name: 'Exploitation & Post-Exploitation',
        description: 'Exploit vulnerabilities and establish persistence',
        techniques: [],
        prerequisites: ['Vulnerabilities identified'],
        expectedOutputs: ['Shell access', 'Data extraction', 'Privilege escalation'],
        successCriteria: ['Administrative access', 'Data compromise', 'Lateral movement']
      }
    ]
  };

  // Mock techniques for each phase
  const mockTechniques: Record<string, HackTricksTechnique[]> = {
    'k8s-recon': [
      {
        id: 'k8s-port-scan',
        name: 'Kubernetes Port Scanning',
        category: 'reconnaissance',
        description: 'Scan for common Kubernetes ports and services',
        commands: [
          {
            tool: 'nmap',
            command: 'nmap -sS -O -p6443,8080,10250,10255,2379,2380 {target}',
            parameters: { target: '' },
            expectedOutput: 'Open ports and service versions',
            dangerLevel: 'safe',
            requiresConfirmation: false
          }
        ],
        tools: ['nmap', 'masscan'],
        mitreAttackId: 'T1046',
        riskLevel: 'low',
        detectionLikelihood: 'medium'
      },
      {
        id: 'k8s-api-discovery',
        name: 'API Server Discovery',
        category: 'reconnaissance',
        description: 'Discover and enumerate Kubernetes API endpoints',
        commands: [
          {
            tool: 'kubectl',
            command: 'kubectl --insecure-skip-tls-verify --server=https://{target}:6443 get pods',
            parameters: { target: '' },
            expectedOutput: 'API server response or authentication error',
            dangerLevel: 'safe',
            requiresConfirmation: false
          }
        ],
        tools: ['kubectl', 'curl'],
        mitreAttackId: 'T1087',
        riskLevel: 'low',
        detectionLikelihood: 'low'
      }
    ],
    'ad-recon': [
      {
        id: 'ad-domain-enum',
        name: 'Domain Enumeration',
        category: 'reconnaissance',
        description: 'Enumerate Active Directory domain information',
        commands: [
          {
            tool: 'ldapsearch',
            command: 'ldapsearch -h {dc} -x -s base "(objectclass=*)" namingContexts',
            parameters: { dc: '' },
            expectedOutput: 'Domain naming contexts and structure',
            dangerLevel: 'safe',
            requiresConfirmation: false
          }
        ],
        tools: ['ldapsearch', 'nslookup', 'dig'],
        mitreAttackId: 'T1018',
        riskLevel: 'low',
        detectionLikelihood: 'low'
      }
    ]
  };

  // Load HackTricks phases for target type
  useEffect(() => {
    const targetPhases = mockPhases[targetType] || mockPhases.web_application;
    setPhases(targetPhases);
    if (targetPhases.length > 0) {
      setCurrentPhase(targetPhases[0]);
      loadTechniques(targetPhases[0].id);
    }
  }, [targetType]);

  // Load techniques for a phase
  const loadTechniques = useCallback(async (phaseId: string) => {
    try {
      // In a real implementation, this would call the API
      const phaseTechniques = mockTechniques[phaseId] || [];
      setTechniques(phaseTechniques);
    } catch (error) {
      console.error('Failed to load techniques:', error);
    }
  }, []);

  // Research with HackTricks/Perplexity
  const performResearch = useCallback(async () => {
    if (!researchQuery.trim()) {
      toast({
        title: "Query Required",
        description: "Please enter a research query",
        variant: "destructive"
      });
      return;
    }

    setIsResearching(true);
    
    try {
      // Query HackTricks knowledge base
      const hackTricksResponse = await modernPentestApi.queryHackTricks(researchQuery);
      
      // Query Perplexity for latest information
      const perplexityResponse = await modernPentestApi.researchWithPerplexity(
        `${researchQuery} site:hacktricks.xyz penetration testing techniques`
      );

      const newQuery: HackTricksQuery = {
        id: Date.now().toString(),
        query: researchQuery,
        timestamp: new Date().toISOString(),
        answer: perplexityResponse.success 
          ? perplexityResponse.data?.answer || 'No answer available'
          : hackTricksResponse.data?.answer || 'Research failed',
        sources: [
          ...(hackTricksResponse.data?.sources || []),
          ...(perplexityResponse.data?.sources || [])
        ],
        relatedTechniques: hackTricksResponse.data?.relatedTechniques || []
      };

      setResearchResults(prev => [newQuery, ...prev]);
      setResearchQuery('');

      toast({
        title: "Research Complete",
        description: "HackTricks and Perplexity research results available"
      });

    } catch (error) {
      toast({
        title: "Research Failed",
        description: error instanceof Error ? error.message : 'Unknown error occurred',
        variant: "destructive"
      });
    } finally {
      setIsResearching(false);
    }
  }, [researchQuery, toast]);

  // Execute technique
  const executeTechnique = useCallback(async (technique: HackTricksTechnique) => {
    if (!sessionId) {
      toast({
        title: "No Active Session",
        description: "Please start a penetration test session first",
        variant: "destructive"
      });
      return;
    }

    setExecutingTechnique(technique.id);

    try {
      const response = await modernPentestApi.executeHackTricksTechnique({
        sessionId,
        techniqueId: technique.id,
        parameters: {}
      });

      if (response.success) {
        setExecutionHistory(prev => [...prev, {
          technique: technique.name,
          timestamp: new Date().toISOString(),
          status: 'completed',
          output: 'Technique executed successfully'
        }]);

        toast({
          title: "Technique Executed",
          description: `${technique.name} completed successfully`
        });
      } else {
        throw new Error(response.error || 'Execution failed');
      }
    } catch (error) {
      toast({
        title: "Execution Failed",
        description: error instanceof Error ? error.message : 'Unknown error occurred',
        variant: "destructive"
      });
    } finally {
      setExecutingTechnique(null);
    }
  }, [sessionId, toast]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-2xl font-bold flex items-center gap-2">
            <BookOpen className="h-6 w-6" />
            HackTricks Methodology
          </h3>
          <p className="text-muted-foreground">
            Structured penetration testing using HackTricks knowledge base and AI research
          </p>
        </div>
        <div className="flex gap-2">
          <Badge variant="outline" className="bg-orange-50 border-orange-200">
            <Brain className="w-4 h-4 mr-1" />
            AI Research
          </Badge>
          <Badge variant="outline" className="bg-blue-50 border-blue-200">
            <BookOpen className="w-4 h-4 mr-1" />
            HackTricks
          </Badge>
        </div>
      </div>

      <Tabs defaultValue="methodology" className="w-full">
        <TabsList className="grid grid-cols-5 w-full">
          <TabsTrigger value="methodology">Methodology</TabsTrigger>
          <TabsTrigger value="research">Research</TabsTrigger>
          <TabsTrigger value="techniques">Techniques</TabsTrigger>
          <TabsTrigger value="execution">Execution</TabsTrigger>
          <TabsTrigger value="knowledge">Knowledge Base</TabsTrigger>
        </TabsList>

        {/* Methodology Tab */}
        <TabsContent value="methodology" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Phases */}
            <Card className="lg:col-span-1">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Target className="h-5 w-5" />
                  Assessment Phases
                </CardTitle>
                <CardDescription>
                  Structured approach for {targetType} security testing
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {phases.map((phase, index) => (
                  <Card 
                    key={phase.id}
                    className={`cursor-pointer transition-all ${
                      currentPhase?.id === phase.id 
                        ? 'border-primary bg-primary/5' 
                        : 'hover:border-primary/50'
                    }`}
                    onClick={() => {
                      setCurrentPhase(phase);
                      loadTechniques(phase.id);
                    }}
                  >
                    <CardContent className="pt-4">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
                          <span className="text-sm font-bold">{index + 1}</span>
                        </div>
                        <div>
                          <h4 className="font-semibold text-sm">{phase.name}</h4>
                          <p className="text-xs text-muted-foreground">{phase.description}</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </CardContent>
            </Card>

            {/* Current Phase Details */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5" />
                  {currentPhase?.name || 'Select Phase'}
                </CardTitle>
                <CardDescription>
                  {currentPhase?.description || 'Choose a phase to view details'}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {currentPhase ? (
                  <div className="space-y-6">
                    {/* Prerequisites */}
                    <div>
                      <h4 className="font-semibold mb-2 flex items-center gap-2">
                        <CheckCircle className="h-4 w-4" />
                        Prerequisites
                      </h4>
                      <ul className="space-y-1">
                        {currentPhase.prerequisites.map((prereq, index) => (
                          <li key={index} className="text-sm text-muted-foreground flex items-center gap-2">
                            <div className="w-1 h-1 bg-primary rounded-full" />
                            {prereq}
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Expected Outputs */}
                    <div>
                      <h4 className="font-semibold mb-2 flex items-center gap-2">
                        <FileText className="h-4 w-4" />
                        Expected Outputs
                      </h4>
                      <ul className="space-y-1">
                        {currentPhase.expectedOutputs.map((output, index) => (
                          <li key={index} className="text-sm text-muted-foreground flex items-center gap-2">
                            <div className="w-1 h-1 bg-green-500 rounded-full" />
                            {output}
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Success Criteria */}
                    <div>
                      <h4 className="font-semibold mb-2 flex items-center gap-2">
                        <Target className="h-4 w-4" />
                        Success Criteria
                      </h4>
                      <ul className="space-y-1">
                        {currentPhase.successCriteria.map((criteria, index) => (
                          <li key={index} className="text-sm text-muted-foreground flex items-center gap-2">
                            <div className="w-1 h-1 bg-blue-500 rounded-full" />
                            {criteria}
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Available Techniques */}
                    <div>
                      <h4 className="font-semibold mb-2 flex items-center gap-2">
                        <Zap className="h-4 w-4" />
                        Available Techniques ({techniques.length})
                      </h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        {techniques.map((technique) => (
                          <Button
                            key={technique.id}
                            variant="outline"
                            size="sm"
                            className="justify-start"
                            onClick={() => setSelectedTechnique(technique)}
                          >
                            <ArrowRight className="w-3 h-3 mr-2" />
                            {technique.name}
                          </Button>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>Select a phase to view methodology details</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Research Tab */}
        <TabsContent value="research" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Research Interface */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Search className="h-5 w-5" />
                  HackTricks Research
                </CardTitle>
                <CardDescription>
                  Query HackTricks knowledge base and Perplexity for latest techniques
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="research-query">Research Query</Label>
                  <Textarea
                    id="research-query"
                    placeholder="e.g., kubernetes privilege escalation techniques, active directory kerberoasting, web application sql injection"
                    value={researchQuery}
                    onChange={(e) => setResearchQuery(e.target.value)}
                    rows={3}
                  />
                </div>

                <Button 
                  onClick={performResearch}
                  disabled={isResearching || !researchQuery.trim()}
                  className="w-full"
                >
                  {isResearching ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Researching...
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4 mr-2" />
                      Research Techniques
                    </>
                  )}
                </Button>

                {/* Quick Research Buttons */}
                <div className="space-y-2">
                  <h4 className="text-sm font-semibold">Quick Research</h4>
                  <div className="flex flex-wrap gap-2">
                    {[
                      'container escape techniques',
                      'kubernetes rbac bypass',
                      'active directory attacks',
                      'web application enumeration'
                    ].map((query) => (
                      <Button
                        key={query}
                        variant="outline"
                        size="sm"
                        onClick={() => setResearchQuery(query)}
                      >
                        {query}
                      </Button>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Research Results */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Lightbulb className="h-5 w-5" />
                  Research Results
                </CardTitle>
                <CardDescription>
                  AI-powered research findings and technique recommendations
                </CardDescription>
              </CardHeader>
              <CardContent>
                {researchResults.length > 0 ? (
                  <ScrollArea className="h-96">
                    <div className="space-y-4">
                      {researchResults.map((result) => (
                        <Card key={result.id} className="border-l-4 border-l-blue-500">
                          <CardContent className="pt-4">
                            <div className="space-y-2">
                              <h4 className="font-semibold text-sm">{result.query}</h4>
                              <p className="text-sm text-muted-foreground">{result.answer}</p>
                              {result.sources.length > 0 && (
                                <div>
                                  <h5 className="text-xs font-semibold">Sources:</h5>
                                  <div className="flex flex-wrap gap-1">
                                    {result.sources.slice(0, 3).map((source, index) => (
                                      <Badge key={index} variant="outline" className="text-xs">
                                        <ExternalLink className="w-2 h-2 mr-1" />
                                        Source {index + 1}
                                      </Badge>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </ScrollArea>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No research results yet</p>
                    <p className="text-sm">Use the research interface to query HackTricks</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Techniques Tab */}
        <TabsContent value="techniques" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Technique List */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Code className="h-5 w-5" />
                  Available Techniques
                </CardTitle>
                <CardDescription>
                  HackTricks techniques for current assessment phase
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {techniques.map((technique) => (
                    <Card 
                      key={technique.id}
                      className={`cursor-pointer transition-all ${
                        selectedTechnique?.id === technique.id 
                          ? 'border-primary bg-primary/5' 
                          : 'hover:border-primary/50'
                      }`}
                      onClick={() => setSelectedTechnique(technique)}
                    >
                      <CardContent className="pt-4">
                        <div className="flex items-start justify-between mb-2">
                          <h4 className="font-semibold text-sm">{technique.name}</h4>
                          <div className="flex gap-1">
                            <Badge 
                              variant={technique.riskLevel === 'critical' || technique.riskLevel === 'high' ? 'destructive' : 'secondary'}
                              className="text-xs"
                            >
                              {technique.riskLevel}
                            </Badge>
                            {technique.mitreAttackId && (
                              <Badge variant="outline" className="text-xs">
                                {technique.mitreAttackId}
                              </Badge>
                            )}
                          </div>
                        </div>
                        <p className="text-xs text-muted-foreground">{technique.description}</p>
                        <div className="flex items-center gap-2 mt-2">
                          <div className="text-xs text-muted-foreground">Tools:</div>
                          {technique.tools.slice(0, 3).map((tool) => (
                            <Badge key={tool} variant="outline" className="text-xs">
                              {tool}
                            </Badge>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Technique Details */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Terminal className="h-5 w-5" />
                  Technique Details
                </CardTitle>
                <CardDescription>
                  Commands and execution details for selected technique
                </CardDescription>
              </CardHeader>
              <CardContent>
                {selectedTechnique ? (
                  <div className="space-y-4">
                    <div>
                      <h4 className="font-semibold mb-2">{selectedTechnique.name}</h4>
                      <p className="text-sm text-muted-foreground mb-4">{selectedTechnique.description}</p>
                    </div>

                    {/* Commands */}
                    <div>
                      <h5 className="font-semibold mb-2">Commands</h5>
                      <div className="space-y-2">
                        {selectedTechnique.commands.map((command, index) => (
                          <Card key={index} className="bg-gray-50 dark:bg-gray-900">
                            <CardContent className="pt-4">
                              <div className="space-y-2">
                                <div className="flex items-center justify-between">
                                  <Badge variant="outline">{command.tool}</Badge>
                                  <Badge 
                                    variant={command.dangerLevel === 'destructive' ? 'destructive' : 'secondary'}
                                  >
                                    {command.dangerLevel}
                                  </Badge>
                                </div>
                                <pre className="text-xs font-mono bg-black text-green-400 p-2 rounded overflow-x-auto">
                                  {command.command}
                                </pre>
                                <p className="text-xs text-muted-foreground">
                                  Expected: {command.expectedOutput}
                                </p>
                              </div>
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    </div>

                    {/* Execute Button */}
                    <Button 
                      onClick={() => executeTechnique(selectedTechnique)}
                      disabled={!sessionId || executingTechnique === selectedTechnique.id}
                      className="w-full"
                    >
                      {executingTechnique === selectedTechnique.id ? (
                        <>
                          <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                          Executing...
                        </>
                      ) : (
                        <>
                          <PlayCircle className="w-4 h-4 mr-2" />
                          Execute Technique
                        </>
                      )}
                    </Button>
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Code className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>Select a technique to view details</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Execution Tab */}
        <TabsContent value="execution" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5" />
                Execution History
              </CardTitle>
              <CardDescription>
                History of executed HackTricks techniques and their results
              </CardDescription>
            </CardHeader>
            <CardContent>
              {executionHistory.length > 0 ? (
                <div className="space-y-3">
                  {executionHistory.map((execution, index) => (
                    <Card key={index} className="border-l-4 border-l-green-500">
                      <CardContent className="pt-4">
                        <div className="flex items-start justify-between mb-2">
                          <h4 className="font-semibold text-sm">{execution.technique}</h4>
                          <Badge variant="default">
                            <CheckCircle className="w-3 h-3 mr-1" />
                            {execution.status}
                          </Badge>
                        </div>
                        <p className="text-sm text-muted-foreground">{execution.output}</p>
                        <div className="text-xs text-muted-foreground mt-2">
                          Executed: {new Date(execution.timestamp).toLocaleString()}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <Clock className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No techniques executed yet</p>
                  <p className="text-sm">Execute techniques to see execution history</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Knowledge Base Tab */}
        <TabsContent value="knowledge" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              { name: 'Linux Privilege Escalation', icon: Server, count: '150+ techniques' },
              { name: 'Windows Privilege Escalation', icon: Server, count: '200+ techniques' },
              { name: 'Network Pivoting', icon: Network, count: '75+ techniques' },
              { name: 'Web Application Security', icon: Globe, count: '300+ techniques' },
              { name: 'Active Directory', icon: Database, count: '100+ techniques' },
              { name: 'Container Security', icon: Shield, count: '50+ techniques' }
            ].map((category) => (
              <Card key={category.name} className="cursor-pointer hover:shadow-md transition-shadow">
                <CardContent className="pt-6">
                  <div className="flex items-center gap-3 mb-2">
                    <category.icon className="h-5 w-5 text-primary" />
                    <h4 className="font-semibold text-sm">{category.name}</h4>
                  </div>
                  <p className="text-xs text-muted-foreground mb-3">{category.count}</p>
                  <Button size="sm" className="w-full" variant="outline">
                    <ExternalLink className="w-3 h-3 mr-1" />
                    Browse
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>

          <Alert>
            <BookOpen className="h-4 w-4" />
            <AlertDescription>
              HackTricks is a comprehensive penetration testing methodology and knowledge base. 
              Visit{' '}
              <a 
                href="https://book.hacktricks.xyz" 
                target="_blank" 
                rel="noopener noreferrer"
                className="font-medium underline"
              >
                book.hacktricks.xyz
              </a>
              {' '}for the complete collection of techniques and methodologies.
            </AlertDescription>
          </Alert>
        </TabsContent>
      </Tabs>
    </div>
  );
};