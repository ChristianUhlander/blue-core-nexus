/**
 * Automation Workflow Component
 * Shows automated penetration testing workflows and decision trees
 */

import React, { useState, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  Zap, 
  GitBranch, 
  Play, 
  Pause, 
  RotateCcw,
  CheckCircle,
  AlertTriangle,
  Clock,
  ArrowRight,
  Settings,
  Brain,
  Target,
  Activity,
  FileSearch,
  Shield
} from "lucide-react";

interface AutomationStep {
  id: string;
  name: string;
  description: string;
  tool: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  progress: number;
  duration?: number;
  findings?: number;
  nextSteps?: string[];
  conditions?: {
    onSuccess?: string[];
    onFinding?: string[];
    onFailure?: string[];
  };
}

interface WorkflowTemplate {
  id: string;
  name: string;
  description: string;
  category: 'network' | 'web' | 'ad' | 'kubernetes' | 'full';
  steps: AutomationStep[];
  estimatedDuration: number;
  aiDriven: boolean;
}

interface AutomationWorkflowProps {
  sessionId?: string;
  onWorkflowStart?: (workflowId: string) => void;
  onWorkflowStop?: () => void;
  isExecuting?: boolean;
}

export const AutomationWorkflow: React.FC<AutomationWorkflowProps> = ({
  sessionId,
  onWorkflowStart,
  onWorkflowStop,
  isExecuting = false
}) => {
  const [selectedWorkflow, setSelectedWorkflow] = useState<string>('');
  const [currentStep, setCurrentStep] = useState(0);
  const [aiAutomation, setAiAutomation] = useState(true);
  const [adaptiveMode, setAdaptiveMode] = useState(true);
  const [executionHistory, setExecutionHistory] = useState<AutomationStep[]>([]);

  // Predefined workflow templates
  const workflowTemplates: WorkflowTemplate[] = [
    {
      id: 'network_recon',
      name: 'Network Reconnaissance',
      description: 'Automated network discovery and service enumeration',
      category: 'network',
      estimatedDuration: 30,
      aiDriven: true,
      steps: [
        {
          id: 'host_discovery',
          name: 'Host Discovery',
          description: 'Discover live hosts on the network',
          tool: 'nmap',
          status: 'pending',
          progress: 0,
          conditions: {
            onSuccess: ['port_scan'],
            onFailure: ['ping_sweep']
          }
        },
        {
          id: 'port_scan',
          name: 'Port Scanning',
          description: 'Scan for open ports on discovered hosts',
          tool: 'nmap',
          status: 'pending',
          progress: 0,
          conditions: {
            onSuccess: ['service_detection'],
            onFinding: ['vulnerability_scan']
          }
        },
        {
          id: 'service_detection',
          name: 'Service Detection',
          description: 'Identify services and versions',
          tool: 'nmap',
          status: 'pending',
          progress: 0,
          conditions: {
            onSuccess: ['vulnerability_scan'],
            onFinding: ['exploit_search']
          }
        },
        {
          id: 'vulnerability_scan',
          name: 'Vulnerability Assessment',
          description: 'Scan for known vulnerabilities',
          tool: 'nmap',
          status: 'pending',
          progress: 0,
          conditions: {
            onFinding: ['exploit_verification'],
            onSuccess: ['report_generation']
          }
        }
      ]
    },
    {
      id: 'web_assessment',
      name: 'Web Application Assessment',
      description: 'Comprehensive web application security testing',
      category: 'web',
      estimatedDuration: 45,
      aiDriven: true,
      steps: [
        {
          id: 'web_discovery',
          name: 'Web Discovery',
          description: 'Discover web applications and technologies',
          tool: 'nikto',
          status: 'pending',
          progress: 0,
          conditions: {
            onSuccess: ['sql_injection_test']
          }
        },
        {
          id: 'sql_injection_test',
          name: 'SQL Injection Testing',
          description: 'Test for SQL injection vulnerabilities',
          tool: 'sqlmap',
          status: 'pending',
          progress: 0,
          conditions: {
            onFinding: ['database_enumeration'],
            onSuccess: ['xss_test']
          }
        },
        {
          id: 'database_enumeration',
          name: 'Database Enumeration',
          description: 'Enumerate database structure and data',
          tool: 'sqlmap',
          status: 'pending',
          progress: 0,
          conditions: {
            onSuccess: ['privilege_escalation_test']
          }
        },
        {
          id: 'xss_test',
          name: 'Cross-Site Scripting Test',
          description: 'Test for XSS vulnerabilities',
          tool: 'nikto',
          status: 'pending',
          progress: 0
        }
      ]
    },
    {
      id: 'ad_assessment',
      name: 'Active Directory Assessment',
      description: 'Comprehensive AD security evaluation',
      category: 'ad',
      estimatedDuration: 60,
      aiDriven: true,
      steps: [
        {
          id: 'ad_enumeration',
          name: 'AD Enumeration',
          description: 'Enumerate domain structure and objects',
          tool: 'bloodhound',
          status: 'pending',
          progress: 0,
          conditions: {
            onSuccess: ['credential_attacks']
          }
        },
        {
          id: 'credential_attacks',
          name: 'Credential Attacks',
          description: 'Kerberoasting and ASREPRoasting',
          tool: 'crackmapexec',
          status: 'pending',
          progress: 0,
          conditions: {
            onFinding: ['lateral_movement'],
            onSuccess: ['privilege_escalation']
          }
        },
        {
          id: 'lateral_movement',
          name: 'Lateral Movement',
          description: 'Attempt lateral movement across the network',
          tool: 'crackmapexec',
          status: 'pending',
          progress: 0,
          conditions: {
            onSuccess: ['privilege_escalation']
          }
        },
        {
          id: 'privilege_escalation',
          name: 'Privilege Escalation',
          description: 'Attempt to escalate privileges to Domain Admin',
          tool: 'bloodhound',
          status: 'pending',
          progress: 0
        }
      ]
    },
    {
      id: 'k8s_assessment',
      name: 'Kubernetes Security Assessment',
      description: 'Cloud-native container security evaluation',
      category: 'kubernetes',
      estimatedDuration: 40,
      aiDriven: true,
      steps: [
        {
          id: 'cluster_discovery',
          name: 'Cluster Discovery',
          description: 'Discover Kubernetes cluster information',
          tool: 'kube-hunter',
          status: 'pending',
          progress: 0,
          conditions: {
            onSuccess: ['container_assessment']
          }
        },
        {
          id: 'container_assessment',
          name: 'Container Assessment',
          description: 'Assess container runtime security',
          tool: 'kdigger',
          status: 'pending',
          progress: 0,
          conditions: {
            onFinding: ['privilege_escalation_k8s'],
            onSuccess: ['rbac_assessment']
          }
        },
        {
          id: 'rbac_assessment',
          name: 'RBAC Assessment',
          description: 'Evaluate role-based access controls',
          tool: 'kube-hunter',
          status: 'pending',
          progress: 0,
          conditions: {
            onFinding: ['cluster_takeover']
          }
        },
        {
          id: 'privilege_escalation_k8s',
          name: 'Container Escape',
          description: 'Attempt container escape and privilege escalation',
          tool: 'kdigger',
          status: 'pending',
          progress: 0
        }
      ]
    }
  ];

  // Get selected workflow template
  const getSelectedWorkflow = () => {
    return workflowTemplates.find(w => w.id === selectedWorkflow);
  };

  // Start workflow execution
  const startWorkflow = useCallback(() => {
    if (selectedWorkflow && onWorkflowStart) {
      onWorkflowStart(selectedWorkflow);
      setCurrentStep(0);
    }
  }, [selectedWorkflow, onWorkflowStart]);

  // Calculate overall progress
  const calculateProgress = () => {
    const workflow = getSelectedWorkflow();
    if (!workflow) return 0;
    
    const completedSteps = workflow.steps.filter(step => step.status === 'completed').length;
    return (completedSteps / workflow.steps.length) * 100;
  };

  // Get step status icon
  const getStepIcon = (status: AutomationStep['status']) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-success" />;
      case 'running':
        return <Activity className="h-4 w-4 text-primary animate-pulse" />;
      case 'failed':
        return <AlertTriangle className="h-4 w-4 text-destructive" />;
      case 'skipped':
        return <ArrowRight className="h-4 w-4 text-muted-foreground" />;
      default:
        return <Clock className="h-4 w-4 text-muted-foreground" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5" />
            Automation Workflows
          </CardTitle>
          <CardDescription>
            AI-driven automated penetration testing workflows that adapt based on findings
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label>Workflow Template</Label>
              <select
                className="w-full p-2 border rounded-md"
                value={selectedWorkflow}
                onChange={(e) => setSelectedWorkflow(e.target.value)}
              >
                <option value="">Select workflow...</option>
                {workflowTemplates.map((template) => (
                  <option key={template.id} value={template.id}>
                    {template.name} ({template.estimatedDuration}min)
                  </option>
                ))}
              </select>
            </div>
            
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <Switch checked={aiAutomation} onCheckedChange={setAiAutomation} />
                <Label>AI Automation</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Switch checked={adaptiveMode} onCheckedChange={setAdaptiveMode} />
                <Label>Adaptive Mode</Label>
              </div>
            </div>
            
            <div className="space-y-2">
              <Button
                onClick={startWorkflow}
                disabled={!selectedWorkflow || isExecuting}
                className="w-full"
                size="lg"
              >
                {isExecuting ? (
                  <>
                    <Pause className="h-4 w-4 mr-2" />
                    Running...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 mr-2" />
                    Start Workflow
                  </>
                )}
              </Button>
              {isExecuting && onWorkflowStop && (
                <Button
                  onClick={onWorkflowStop}
                  variant="destructive"
                  className="w-full"
                >
                  Stop Workflow
                </Button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Workflow Details */}
      {selectedWorkflow && (
        <Tabs defaultValue="overview" className="w-full">
          <TabsList className="grid grid-cols-3 w-full">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="workflow">Workflow</TabsTrigger>
            <TabsTrigger value="ai-logic">AI Logic</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">{getSelectedWorkflow()?.name}</CardTitle>
                  <CardDescription>{getSelectedWorkflow()?.description}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span>Category:</span>
                    <Badge variant="outline">{getSelectedWorkflow()?.category}</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Duration:</span>
                    <span>{getSelectedWorkflow()?.estimatedDuration} minutes</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>AI-Driven:</span>
                    <Badge variant={getSelectedWorkflow()?.aiDriven ? "default" : "secondary"}>
                      {getSelectedWorkflow()?.aiDriven ? "Yes" : "No"}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Steps:</span>
                    <span>{getSelectedWorkflow()?.steps.length}</span>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-lg">Progress</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <Progress value={calculateProgress()} className="h-3" />
                  <div className="text-sm text-muted-foreground">
                    {Math.round(calculateProgress())}% complete
                  </div>
                  
                  {isExecuting && (
                    <Alert>
                      <Brain className="h-4 w-4" />
                      <AlertDescription>
                        AI is analyzing results and determining next steps automatically
                      </AlertDescription>
                    </Alert>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Workflow Tab */}
          <TabsContent value="workflow" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <GitBranch className="h-5 w-5" />
                  Execution Flow
                </CardTitle>
                <CardDescription>
                  Adaptive workflow that changes based on findings and AI analysis
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-96">
                  <div className="space-y-4">
                    {getSelectedWorkflow()?.steps.map((step, index) => (
                      <div
                        key={step.id}
                        className={`border rounded-lg p-4 ${
                          currentStep === index ? 'border-primary bg-primary/5' : ''
                        }`}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            {getStepIcon(step.status)}
                            <span className="font-medium">{step.name}</span>
                            <Badge variant="outline">{step.tool}</Badge>
                          </div>
                          <div className="flex items-center gap-2">
                            {step.findings && step.findings > 0 && (
                              <Badge variant="destructive">
                                {step.findings} findings
                              </Badge>
                            )}
                            <Badge variant="secondary">{step.status}</Badge>
                          </div>
                        </div>
                        
                        <p className="text-sm text-muted-foreground mb-2">
                          {step.description}
                        </p>
                        
                        {step.status === 'running' && (
                          <Progress value={step.progress} className="h-2 mb-2" />
                        )}
                        
                        {step.conditions && (
                          <div className="mt-2 space-y-1">
                            <p className="text-xs font-medium text-muted-foreground">Conditional Logic:</p>
                            {step.conditions.onSuccess && (
                              <div className="text-xs">
                                <span className="text-success">✓ On Success:</span> {step.conditions.onSuccess.join(', ')}
                              </div>
                            )}
                            {step.conditions.onFinding && (
                              <div className="text-xs">
                                <span className="text-warning">! On Finding:</span> {step.conditions.onFinding.join(', ')}
                              </div>
                            )}
                            {step.conditions.onFailure && (
                              <div className="text-xs">
                                <span className="text-destructive">✗ On Failure:</span> {step.conditions.onFailure.join(', ')}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>

          {/* AI Logic Tab */}
          <TabsContent value="ai-logic" className="space-y-4">
            <div className="grid gap-4">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Brain className="h-5 w-5" />
                    AI Decision Engine
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <Alert>
                    <Brain className="h-4 w-4" />
                    <AlertDescription>
                      <strong>Adaptive Intelligence:</strong> The AI analyzes each step's output to determine the most effective next actions, adapting the workflow in real-time based on discovered vulnerabilities and attack surface.
                    </AlertDescription>
                  </Alert>
                  
                  <div className="space-y-3">
                    <div className="border-l-4 border-primary pl-4">
                      <h4 className="font-medium">Finding-Based Branching</h4>
                      <p className="text-sm text-muted-foreground">
                        When vulnerabilities are discovered, the AI automatically prioritizes exploitation paths and adds relevant steps to maximize impact.
                      </p>
                    </div>
                    
                    <div className="border-l-4 border-success pl-4">
                      <h4 className="font-medium">Success Path Optimization</h4>
                      <p className="text-sm text-muted-foreground">
                        Successful steps trigger deeper enumeration and advanced techniques targeting the specific environment discovered.
                      </p>
                    </div>
                    
                    <div className="border-l-4 border-warning pl-4">
                      <h4 className="font-medium">Failure Recovery</h4>
                      <p className="text-sm text-muted-foreground">
                        Failed steps trigger alternative approaches and fallback techniques, ensuring comprehensive coverage.
                      </p>
                    </div>
                    
                    <div className="border-l-4 border-info pl-4">
                      <h4 className="font-medium">Risk Assessment</h4>
                      <p className="text-sm text-muted-foreground">
                        AI continuously evaluates risk vs. reward, avoiding potentially destructive actions while maximizing discovery.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Automation Capabilities</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <h4 className="font-medium flex items-center gap-2">
                        <Target className="h-4 w-4" />
                        Target Adaptation
                      </h4>
                      <ul className="text-sm text-muted-foreground space-y-1">
                        <li>• Dynamic port range adjustment</li>
                        <li>• Service-specific payload selection</li>
                        <li>• Environment-aware technique selection</li>
                      </ul>
                    </div>
                    
                    <div className="space-y-2">
                      <h4 className="font-medium flex items-center gap-2">
                        <Shield className="h-4 w-4" />
                        Evasion Intelligence
                      </h4>
                      <ul className="text-sm text-muted-foreground space-y-1">
                        <li>• IDS/IPS detection and evasion</li>
                        <li>• Rate limiting and timing adjustment</li>
                        <li>• Stealth mode activation</li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
};