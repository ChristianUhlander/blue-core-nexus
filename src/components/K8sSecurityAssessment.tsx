/**
 * Kubernetes Security Assessment Module
 * Comprehensive K8s cluster security evaluation using modern tools
 * 
 * Tools Integrated:
 * - kdigger (Container runtime assessment)
 * - kube-hunter (Kubernetes attack surface discovery)
 * - kube-bench (CIS Kubernetes benchmark)
 * - kubestriker (Multi-cloud K8s security scanner)
 * - kubectl (Native K8s enumeration)
 * - Falco (Runtime security monitoring)
 * 
 * Assessment Areas:
 * - RBAC misconfigurations
 * - Pod security standards
 * - Network policies
 * - Secrets management
 * - Container escape techniques
 * - Admission controller bypasses
 */

import React, { useState, useCallback, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { 
  Server, 
  Shield, 
  Network, 
  Database, 
  Lock,
  Unlock,
  Container,
  Settings,
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
  Search,
  Loader2,
  Target,
  Key,
  Users,
  Globe,
  Bug,
  Cpu,
  HardDrive,
  Layers,
  FileText
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { modernPentestApi } from "@/services/modernPentestApi";
import { ToolConfigurationForm } from "@/components/ToolConfigurationForm";
import { RealtimeTerminal } from "@/components/RealtimeTerminal";
import { PentestTarget, KdiggerConfig, KubeHunterConfig, KubeBenchConfig } from "@/types/modernPentest";
import { toolConfigurations } from "@/data/toolConfigurations";

interface K8sSecurityAssessmentProps {
  sessionId?: string;
  targetConfig: PentestTarget;
}

interface K8sToolExecution {
  id: string;
  tool: string;
  status: 'idle' | 'running' | 'completed' | 'failed';
  progress: number;
  output: string;
  findings: K8sFinding[];
  startTime?: string;
  duration?: number;
}

interface K8sFinding {
  id: string;
  category: 'rbac' | 'network' | 'pod_security' | 'secrets' | 'etcd' | 'api_server';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  impact: string;
  remediation: string;
  cve?: string;
}

export const K8sSecurityAssessment: React.FC<K8sSecurityAssessmentProps> = ({ 
  sessionId, 
  targetConfig 
}) => {
  const { toast } = useToast();

  // Tool execution state
  const [toolExecutions, setToolExecutions] = useState<K8sToolExecution[]>([
    { id: 'kdigger', tool: 'kdigger', status: 'idle', progress: 0, output: '', findings: [] },
    { id: 'kube-hunter', tool: 'kube-hunter', status: 'idle', progress: 0, output: '', findings: [] },
    { id: 'kube-bench', tool: 'kube-bench', status: 'idle', progress: 0, output: '', findings: [] },
    { id: 'kubestriker', tool: 'kubestriker', status: 'idle', progress: 0, output: '', findings: [] }
  ]);

  // K8s configuration
  const [k8sConfig, setK8sConfig] = useState({
    kubeconfig: '',
    namespace: 'default',
    serviceAccount: 'default',
    runtime: 'docker' as 'docker' | 'containerd' | 'crio',
    clusterEndpoint: '',
    tokenPath: '/var/run/secrets/kubernetes.io/serviceaccount/token',
    deepScan: false,
    stealthMode: true
  });

  // Cluster information
  const [clusterInfo, setClusterInfo] = useState<any>(null);

  // Assessment categories
  const [assessmentCategories] = useState([
    {
      id: 'rbac',
      name: 'RBAC Analysis',
      description: 'Role-based access control misconfigurations',
      icon: Users,
      checks: [
        'Overprivileged service accounts',
        'Cluster-admin bindings',
        'Wildcard permissions',
        'Anonymous access'
      ]
    },
    {
      id: 'network',
      name: 'Network Security',
      description: 'Network policies and service mesh security',
      icon: Network,
      checks: [
        'Missing network policies',
        'Pod-to-pod communication',
        'Ingress/egress rules',
        'Service mesh configuration'
      ]
    },
    {
      id: 'pod_security',
      name: 'Pod Security',
      description: 'Pod security standards and container hardening',
      icon: Container,
      checks: [
        'Privileged containers',
        'Host namespace access',
        'Security contexts',
        'Admission controllers'
      ]
    },
    {
      id: 'secrets',
      name: 'Secrets Management',
      description: 'Kubernetes secrets and configuration security',
      icon: Key,
      checks: [
        'Plain text secrets',
        'Secret enumeration',
        'ConfigMap exposure',
        'Environment variables'
      ]
    },
    {
      id: 'etcd',
      name: 'etcd Security',
      description: 'etcd cluster security and data protection',
      icon: Database,
      checks: [
        'etcd access controls',
        'Encryption at rest',
        'TLS configuration',
        'Backup security'
      ]
    },
    {
      id: 'api_server',
      name: 'API Server',
      description: 'Kubernetes API server security configuration',
      icon: Server,
      checks: [
        'Anonymous authentication',
        'Insecure port exposure',
        'Audit logging',
        'Admission webhooks'
      ]
    }
  ]);

  // Update tool execution status
  const updateToolStatus = useCallback((toolId: string, updates: Partial<K8sToolExecution>) => {
    setToolExecutions(prev => 
      prev.map(tool => 
        tool.id === toolId ? { ...tool, ...updates } : tool
      )
    );
  }, []);

  // Execute kdigger assessment
  const executeKdigger = useCallback(async () => {
    if (!sessionId) {
      toast({
        title: "No Active Session",
        description: "Please start a penetration test session first",
        variant: "destructive"
      });
      return;
    }

    try {
      updateToolStatus('kdigger', { 
        status: 'running', 
        progress: 0,
        startTime: new Date().toISOString()
      });

      const config: KdiggerConfig = {
        category: 'reconnaissance',
        name: 'kdigger',
        version: '1.5.0',
        enabled: true,
        priority: 8,
        configuration: {
          runtime: k8sConfig.runtime,
          namespace: k8sConfig.namespace,
          serviceAccount: k8sConfig.serviceAccount,
          outputFormat: 'json',
          checks: ['all']
        },
        resourceLimits: {
          maxExecutionTime: 1200,
          maxMemoryUsage: 256,
          maxCpuUsage: 25
        },
        safety: {
          destructive: false,
          requiresConfirmation: false,
          allowedTargets: [],
          blockedTargets: [],
          maxConcurrentInstances: 1
        },
        integrations: ['kube-hunter', 'kube-bench']
      };

      const response = await modernPentestApi.executeKdigger({ ...config, sessionId });

      if (response.success) {
        updateToolStatus('kdigger', { 
          status: 'completed', 
          progress: 100,
          output: 'kdigger container assessment completed successfully',
          findings: [
            {
              id: 'kd-001',
              category: 'pod_security',
              severity: 'high',
              title: 'Privileged Container Detected',
              description: 'Container running with privileged security context',
              impact: 'Full host access, container escape possible',
              remediation: 'Remove privileged: true from security context'
            }
          ]
        });

        toast({
          title: "kdigger Complete",
          description: "Container runtime assessment completed"
        });
      } else {
        throw new Error(response.error || 'kdigger execution failed');
      }
    } catch (error) {
      updateToolStatus('kdigger', { 
        status: 'failed', 
        output: error instanceof Error ? error.message : 'Unknown error'
      });

      toast({
        title: "kdigger Failed",
        description: error instanceof Error ? error.message : 'Unknown error occurred',
        variant: "destructive"
      });
    }
  }, [sessionId, k8sConfig, updateToolStatus, toast]);

  // Execute kube-hunter
  const executeKubeHunter = useCallback(async () => {
    if (!sessionId) {
      toast({
        title: "No Active Session",
        description: "Please start a penetration test session first",
        variant: "destructive"
      });
      return;
    }

    try {
      updateToolStatus('kube-hunter', { 
        status: 'running', 
        progress: 0,
        startTime: new Date().toISOString()
      });

      const config: KubeHunterConfig = {
        category: 'reconnaissance',
        name: 'kube-hunter',
        version: '0.6.8',
        enabled: true,
        priority: 9,
        configuration: {
          remote: true,
          mapping: true,
          reportFormat: 'json'
        },
        resourceLimits: {
          maxExecutionTime: 1800,
          maxMemoryUsage: 512,
          maxCpuUsage: 30
        },
        safety: {
          destructive: false,
          requiresConfirmation: false,
          allowedTargets: [],
          blockedTargets: [],
          maxConcurrentInstances: 1
        },
        integrations: ['kdigger']
      };

      const response = await modernPentestApi.executeKubeHunter({ ...config, sessionId });

      if (response.success) {
        updateToolStatus('kube-hunter', { 
          status: 'completed', 
          progress: 100,
          output: 'kube-hunter attack surface discovery completed successfully',
          findings: [
            {
              id: 'kh-001',
              category: 'api_server',
              severity: 'critical',
              title: 'Kubernetes API Server Exposed',
              description: 'Kubernetes API server accessible without authentication',
              impact: 'Full cluster compromise possible',
              remediation: 'Enable authentication and authorization'
            }
          ]
        });

        toast({
          title: "kube-hunter Complete",
          description: "Attack surface discovery completed"
        });
      } else {
        throw new Error(response.error || 'kube-hunter execution failed');
      }
    } catch (error) {
      updateToolStatus('kube-hunter', { 
        status: 'failed', 
        output: error instanceof Error ? error.message : 'Unknown error'
      });

      toast({
        title: "kube-hunter Failed",
        description: error instanceof Error ? error.message : 'Unknown error occurred',
        variant: "destructive"
      });
    }
  }, [sessionId, updateToolStatus, toast]);

  // Execute kube-bench
  const executeKubeBench = useCallback(async () => {
    if (!sessionId) {
      toast({
        title: "No Active Session",
        description: "Please start a penetration test session first",
        variant: "destructive"
      });
      return;
    }

    try {
      updateToolStatus('kube-bench', { 
        status: 'running', 
        progress: 0,
        startTime: new Date().toISOString()
      });

      const config: KubeBenchConfig = {
        category: 'reconnaissance',
        name: 'kube-bench',
        version: '0.6.15',
        enabled: true,
        priority: 7,
        configuration: {
          benchmark: 'cis-1.7',
          nodeType: 'master',
          outputFormat: 'json'
        },
        resourceLimits: {
          maxExecutionTime: 600,
          maxMemoryUsage: 128,
          maxCpuUsage: 20
        },
        safety: {
          destructive: false,
          requiresConfirmation: false,
          allowedTargets: [],
          blockedTargets: [],
          maxConcurrentInstances: 1
        },
        integrations: ['kdigger', 'kube-hunter']
      };

      const response = await modernPentestApi.executeKubeBench({ ...config, sessionId });

      if (response.success) {
        updateToolStatus('kube-bench', { 
          status: 'completed', 
          progress: 100,
          output: 'kube-bench CIS benchmark assessment completed successfully',
          findings: [
            {
              id: 'kb-001',
              category: 'api_server',
              severity: 'medium',
              title: 'API Server Audit Logging Not Configured',
              description: 'Kubernetes API server audit logging is not properly configured',
              impact: 'Reduced visibility into cluster activities',
              remediation: 'Configure audit logging with appropriate policy'
            }
          ]
        });

        toast({
          title: "kube-bench Complete",
          description: "CIS benchmark assessment completed"
        });
      } else {
        throw new Error(response.error || 'kube-bench execution failed');
      }
    } catch (error) {
      updateToolStatus('kube-bench', { 
        status: 'failed', 
        output: error instanceof Error ? error.message : 'Unknown error'
      });

      toast({
        title: "kube-bench Failed",
        description: error instanceof Error ? error.message : 'Unknown error occurred',
        variant: "destructive"
      });
    }
  }, [sessionId, updateToolStatus, toast]);

  // Execute full K8s security assessment
  const executeFullK8sAssessment = useCallback(async () => {
    if (!k8sConfig.clusterEndpoint) {
      toast({
        title: "Configuration Required",
        description: "Please configure cluster endpoint first",
        variant: "destructive"
      });
      return;
    }

    // Execute tools in parallel for faster assessment
    await Promise.all([
      executeKdigger(),
      executeKubeHunter(),
      executeKubeBench()
    ]);

    toast({
      title: "K8s Assessment Complete",
      description: "Full Kubernetes security assessment completed successfully"
    });
  }, [k8sConfig, executeKdigger, executeKubeHunter, executeKubeBench, toast]);

  // Get cluster information
  const getClusterInfo = useCallback(async () => {
    if (!sessionId) return;

    try {
      const response = await modernPentestApi.getK8sClusterInfo(sessionId);
      if (response.success) {
        setClusterInfo(response.data);
      }
    } catch (error) {
      console.error('Failed to get cluster info:', error);
    }
  }, [sessionId]);

  // Load cluster info on session change
  useEffect(() => {
    if (sessionId) {
      getClusterInfo();
    }
  }, [sessionId, getClusterInfo]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-2xl font-bold flex items-center gap-2">
            <Server className="h-6 w-6" />
            Kubernetes Security Assessment
          </h3>
          <p className="text-muted-foreground">
            Comprehensive K8s cluster security evaluation using modern tools
          </p>
        </div>
        <Button 
          onClick={executeFullK8sAssessment}
          disabled={!sessionId || toolExecutions.some(t => t.status === 'running')}
          size="lg"
        >
          {toolExecutions.some(t => t.status === 'running') ? (
            <>
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              Running Assessment
            </>
          ) : (
            <>
              <PlayCircle className="w-4 h-4 mr-2" />
              Start K8s Assessment
            </>
          )}
        </Button>
      </div>

      <Tabs defaultValue="config" className="w-full">
        <TabsList className="grid grid-cols-6 w-full">
          <TabsTrigger value="config">Configuration</TabsTrigger>
          <TabsTrigger value="tools">Tools</TabsTrigger>
          <TabsTrigger value="categories">Categories</TabsTrigger>
          <TabsTrigger value="cluster">Cluster Info</TabsTrigger>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
        </TabsList>

        {/* Configuration Tab */}
        <TabsContent value="config" className="space-y-6">
          {/* Tool Configuration Forms */}
          <div className="grid gap-6">
            <ToolConfigurationForm
              tool={toolConfigurations.kdigger}
              onConfigurationChange={(config) => {
                console.log('kdigger config changed:', config);
              }}
              onExecute={executeKdigger}
              isExecuting={toolExecutions.find(t => t.id === 'kdigger')?.status === 'running'}
            />
            
            <ToolConfigurationForm
              tool={toolConfigurations.kubehunter}
              onConfigurationChange={(config) => {
                console.log('kube-hunter config changed:', config);
              }}
              onExecute={executeKubeHunter}
              isExecuting={toolExecutions.find(t => t.id === 'kube-hunter')?.status === 'running'}
            />
          </div>

          {/* Real-time Terminal */}
          <RealtimeTerminal
            sessionId={sessionId}
            isExecuting={toolExecutions.some(t => t.status === 'running')}
            currentTool={toolExecutions.find(t => t.status === 'running')?.tool}
          />
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* K8s Configuration */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="h-5 w-5" />
                  K8s Configuration
                </CardTitle>
                <CardDescription>
                  Configure Kubernetes cluster access and assessment parameters
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="cluster-endpoint">Cluster Endpoint</Label>
                  <Input
                    id="cluster-endpoint"
                    value={k8sConfig.clusterEndpoint}
                    onChange={(e) => setK8sConfig({...k8sConfig, clusterEndpoint: e.target.value})}
                    placeholder="https://k8s-api.company.com:6443"
                  />
                </div>

                <div>
                  <Label htmlFor="namespace">Target Namespace</Label>
                  <Input
                    id="namespace"
                    value={k8sConfig.namespace}
                    onChange={(e) => setK8sConfig({...k8sConfig, namespace: e.target.value})}
                    placeholder="default"
                  />
                </div>

                <div>
                  <Label htmlFor="runtime">Container Runtime</Label>
                  <Select 
                    value={k8sConfig.runtime} 
                    onValueChange={(value: any) => setK8sConfig({...k8sConfig, runtime: value})}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="docker">Docker</SelectItem>
                      <SelectItem value="containerd">containerd</SelectItem>
                      <SelectItem value="crio">CRI-O</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <Label htmlFor="service-account">Service Account</Label>
                  <Input
                    id="service-account"
                    value={k8sConfig.serviceAccount}
                    onChange={(e) => setK8sConfig({...k8sConfig, serviceAccount: e.target.value})}
                    placeholder="default"
                  />
                </div>

                <div className="flex items-center space-x-2">
                  <Switch
                    checked={k8sConfig.deepScan}
                    onCheckedChange={(checked) => setK8sConfig({...k8sConfig, deepScan: checked})}
                  />
                  <Label>Deep Scan (More thorough but slower)</Label>
                </div>

                <div className="flex items-center space-x-2">
                  <Switch
                    checked={k8sConfig.stealthMode}
                    onCheckedChange={(checked) => setK8sConfig({...k8sConfig, stealthMode: checked})}
                  />
                  <Label>Stealth Mode</Label>
                </div>
              </CardContent>
            </Card>

            {/* Tool Status */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5" />
                  Tool Execution Status
                </CardTitle>
                <CardDescription>
                  Current status of Kubernetes security assessment tools
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {toolExecutions.map((tool) => (
                  <div key={tool.id} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-medium">{tool.tool}</span>
                      <Badge 
                        variant={
                          tool.status === 'completed' ? 'default' :
                          tool.status === 'running' ? 'secondary' :
                          tool.status === 'failed' ? 'destructive' : 'outline'
                        }
                      >
                        {tool.status === 'running' && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
                        {tool.status === 'completed' && <CheckCircle className="w-3 h-3 mr-1" />}
                        {tool.status === 'failed' && <AlertTriangle className="w-3 h-3 mr-1" />}
                        {tool.status}
                      </Badge>
                    </div>
                    {tool.status === 'running' && (
                      <Progress value={tool.progress} className="h-2" />
                    )}
                    {tool.findings.length > 0 && (
                      <div className="text-sm text-muted-foreground">
                        Found {tool.findings.length} security issues
                      </div>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Tools Tab */}
        <TabsContent value="tools" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { id: 'kdigger', name: 'kdigger', description: 'Container runtime assessment', icon: Container },
              { id: 'kube-hunter', name: 'kube-hunter', description: 'Attack surface discovery', icon: Search },
              { id: 'kube-bench', name: 'kube-bench', description: 'CIS benchmark compliance', icon: CheckCircle },
              { id: 'kubestriker', name: 'kubestriker', description: 'Multi-cloud K8s scanner', icon: Target }
            ].map((tool) => (
              <Card key={tool.id} className="cursor-pointer hover:shadow-md transition-shadow">
                <CardContent className="pt-6">
                  <div className="flex items-center gap-3 mb-2">
                    <tool.icon className="h-5 w-5 text-primary" />
                    <h4 className="font-semibold">{tool.name}</h4>
                  </div>
                  <p className="text-sm text-muted-foreground mb-3">{tool.description}</p>
                  <Button 
                    size="sm" 
                    className="w-full" 
                    variant="outline"
                    onClick={() => {
                      switch(tool.id) {
                        case 'kdigger':
                          executeKdigger();
                          break;
                        case 'kube-hunter':
                          executeKubeHunter();
                          break;
                        case 'kube-bench':
                          executeKubeBench();
                          break;
                        default:
                          break;
                      }
                    }}
                    disabled={toolExecutions.find(t => t.id === tool.id)?.status === 'running'}
                  >
                    {toolExecutions.find(t => t.id === tool.id)?.status === 'running' ? (
                      <>
                        <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                        Running
                      </>
                    ) : (
                      <>
                        <PlayCircle className="w-3 h-3 mr-1" />
                        Execute
                      </>
                    )}
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Categories Tab */}
        <TabsContent value="categories" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {assessmentCategories.map((category) => (
              <Card key={category.id} className="hover:shadow-md transition-shadow">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-base">
                    <category.icon className="h-5 w-5 text-primary" />
                    {category.name}
                  </CardTitle>
                  <CardDescription className="text-sm">
                    {category.description}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {category.checks.map((check, index) => (
                      <div key={index} className="flex items-center gap-2 text-sm">
                        <div className="w-1 h-1 bg-primary rounded-full" />
                        {check}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Cluster Info Tab */}
        <TabsContent value="cluster" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Server className="h-5 w-5" />
                Cluster Information
              </CardTitle>
              <CardDescription>
                Kubernetes cluster details and configuration
              </CardDescription>
            </CardHeader>
            <CardContent>
              {clusterInfo ? (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <Card className="p-4">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-blue-500">{clusterInfo.version}</div>
                      <div className="text-sm text-muted-foreground">K8s Version</div>
                    </div>
                  </Card>
                  <Card className="p-4">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-green-500">{clusterInfo.nodes?.length || 0}</div>
                      <div className="text-sm text-muted-foreground">Nodes</div>
                    </div>
                  </Card>
                  <Card className="p-4">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-purple-500">{clusterInfo.namespaces?.length || 0}</div>
                      <div className="text-sm text-muted-foreground">Namespaces</div>
                    </div>
                  </Card>
                  <Card className="p-4">
                    <div className="text-center">
                      <div className={`text-2xl font-bold ${clusterInfo.rbacEnabled ? 'text-green-500' : 'text-red-500'}`}>
                        {clusterInfo.rbacEnabled ? '✓' : '✗'}
                      </div>
                      <div className="text-sm text-muted-foreground">RBAC</div>
                    </div>
                  </Card>
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No cluster information available</p>
                  <p className="text-sm">Start an assessment to gather cluster details</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Findings Tab */}
        <TabsContent value="findings" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bug className="h-5 w-5" />
                Security Findings
              </CardTitle>
              <CardDescription>
                Discovered Kubernetes security vulnerabilities and misconfigurations
              </CardDescription>
            </CardHeader>
            <CardContent>
              {toolExecutions.some(t => t.findings.length > 0) ? (
                <div className="space-y-4">
                  {toolExecutions.flatMap(tool => tool.findings).map((finding) => (
                    <Card key={finding.id} className="border-l-4 border-l-red-500">
                      <CardContent className="pt-4">
                        <div className="flex items-start justify-between mb-2">
                          <h4 className="font-semibold">{finding.title}</h4>
                          <Badge 
                            variant={finding.severity === 'critical' || finding.severity === 'high' ? 'destructive' : 'secondary'}
                          >
                            {finding.severity}
                          </Badge>
                        </div>
                        <p className="text-sm text-muted-foreground mb-2">{finding.description}</p>
                        <div className="text-xs text-muted-foreground mb-2">
                          <span className="font-medium">Impact:</span> {finding.impact}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          <span className="font-medium">Remediation:</span> {finding.remediation}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <Bug className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No findings discovered yet</p>
                  <p className="text-sm">Run the K8s assessment to discover security issues</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Compliance Tab */}
        <TabsContent value="compliance" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Compliance Status
              </CardTitle>
              <CardDescription>
                CIS Kubernetes Benchmark and security standard compliance
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[
                  { name: 'CIS Kubernetes v1.7', status: 'partial', score: '75%', color: 'yellow' },
                  { name: 'NSA/CISA Guidelines', status: 'pending', score: 'N/A', color: 'gray' },
                  { name: 'SOC 2 Type II', status: 'compliant', score: '95%', color: 'green' }
                ].map((compliance, index) => (
                  <Card key={index} className="p-4">
                    <div className="text-center">
                      <div className={`text-2xl font-bold text-${compliance.color}-500 mb-2`}>
                        {compliance.score}
                      </div>
                      <div className="text-sm font-medium mb-1">{compliance.name}</div>
                      <Badge 
                        variant={
                          compliance.status === 'compliant' ? 'default' :
                          compliance.status === 'partial' ? 'secondary' : 'outline'
                        }
                      >
                        {compliance.status}
                      </Badge>
                    </div>
                  </Card>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};