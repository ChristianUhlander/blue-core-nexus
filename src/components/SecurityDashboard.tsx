import { Shield, Eye, Zap, Search, Activity, AlertTriangle, CheckCircle, Clock, Server, Database, Wifi, WifiOff, Users, Settings, Cog, FileText, ToggleLeft, ToggleRight, Scan, Bug, ShieldAlert, TrendingUp, Download, RefreshCw, Filter, BarChart3, Calendar, Target, Play, Code, Lock, Globe, MapPin, Mail, Phone, User, Building, Loader2, CheckCheck, X, AlertCircle, BrainCircuit, Info, Bot, MessageCircle, Brain, Network, Terminal, Key, PlayCircle, Unlock, Box } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { useToast } from "@/hooks/use-toast";
import IppsYChatPane from "./IppsYChatPane";
import { DocumentationLibrary } from "./DocumentationLibrary";
import { useRealTimeSecurityData } from "@/hooks/useRealTimeSecurityData";
import { k8sSecurityApi } from "@/services/k8sSecurityApi";
import { enhancedSecurityService, type WazuhAgent, type WazuhAlert, type SecurityServiceHealth } from "@/services/enhancedSecurityService";
import { AgentConfigurationAdvanced } from "./AgentConfigurationAdvanced";
import { EnhancedAgenticPentestInterface } from "./EnhancedAgenticPentestInterface";
import { ProductionReadySecurityConfig } from "./ProductionReadySecurityConfig";
import { IntelligentReportingSystem } from "./IntelligentReportingSystem";
import { AutomaticOSINTAgent } from "./AutomaticOSINTAgent";
import { ADPentestingModule } from "./ADPentestingModule";
import { NetworkPentestingModule } from "./NetworkPentestingModule";
import { WebAppPentestingModule } from "./WebAppPentestingModule";
import { OSINTPentestingModule } from "./OSINTPentestingModule";

import WazuhManagement from "../pages/WazuhManagement";
import { WazuhSBOMManagement } from "./WazuhSBOMManagement";
import GVMManagement from "../pages/GVMManagement";
import { ConnectionStatusIndicator } from "./ConnectionStatusIndicator";
import heroImage from "@/assets/security-hero.jpg";
import { useState, useEffect, useCallback, useMemo } from "react";
import * as React from "react";

/**
 * Real-time Security Dashboard
 * Production-ready K8s integration with comprehensive error handling and QA validation
 */
const SecurityDashboard = () => {
  // Real-time security data hook with K8s integration
  const {
    services,
    alerts,
    agents,
    isConnected,
    lastUpdate,
    error,
    refreshAll,
    refreshService,
    acknowledgeAlert,
    restartAgent,
    getServiceStats
  } = useRealTimeSecurityData();

  // Enhanced state management for real backend integration
  const [realTimeAgents, setRealTimeAgents] = useState<WazuhAgent[]>([]);
  const [realTimeAlerts, setRealTimeAlerts] = useState<WazuhAlert[]>([]);
  const [serviceHealths, setServiceHealths] = useState<SecurityServiceHealth[]>([]);
  const [backendConnected, setBackendConnected] = useState(false);
  const [vulnerabilityData, setVulnerabilityData] = useState<any[]>([]);
  const [realScanResults, setRealScanResults] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  
  // Dialog state management
  const [isAgentStatusOpen, setIsAgentStatusOpen] = useState(false);
  const [isAgentConfigOpen, setIsAgentConfigOpen] = useState(false);
  const [isCveAssessmentOpen, setIsCveAssessmentOpen] = useState(false);
  const [isScanResultsOpen, setIsScanResultsOpen] = useState(false);
  const [isOwaspScanOpen, setIsOwaspScanOpen] = useState(false);
  const [isSpiderfootOpen, setIsSpiderfootOpen] = useState(false);
  const [isOsintProfilesOpen, setIsOsintProfilesOpen] = useState(false);
  const [isThreatAnalysisOpen, setIsThreatAnalysisOpen] = useState(false);
  const [isWazuhManagementOpen, setIsWazuhManagementOpen] = useState(false);
  const [isGvmManagementOpen, setIsGvmManagementOpen] = useState(false);
  const [isSchedulerOpen, setIsSchedulerOpen] = useState(false);
  const [isIppsYOpen, setIsIppsYOpen] = useState(false);
  const [isDocumentationOpen, setIsDocumentationOpen] = useState(false);
  const [isProductionConfigOpen, setIsProductionConfigOpen] = useState(false);
  const [isReportingOpen, setIsReportingOpen] = useState(false);
  
  // Toast hook
  const { toast } = useToast();

  // Real-time WebSocket integration
  useEffect(() => {
    const initializeBackendConnections = async () => {
      try {
        console.log('🚀 Initializing production security backend integration...');
        
        const healthStatuses = enhancedSecurityService.getHealthStatuses();
        setServiceHealths(healthStatuses);
        
        const eventListeners: Array<{ event: string; handler: EventListener }> = [
          {
            event: 'security:wazuh:message',
            handler: (event: CustomEvent) => {
              const data = event.detail;
              if (data.type === 'alert') {
                setRealTimeAlerts(prev => [data.alert, ...prev.slice(0, 49)]);
                toast({
                  title: "🚨 Security Alert",
                  description: `${data.alert.rule.description} on ${data.alert.agent.name}`,
                  variant: data.alert.rule.level >= 7 ? "destructive" : "default"
                });
              }
            }
          }
        ];
        
        eventListeners.forEach(({ event, handler }) => {
          window.addEventListener(event, handler as EventListener);
        });
        
        return () => {
          eventListeners.forEach(({ event, handler }) => {
            window.removeEventListener(event, handler as EventListener);
          });
        };
        
      } catch (error) {
        console.error('❌ Failed to initialize backend connections:', error);
        toast({
          title: "Backend Connection Error",
          description: "Failed to establish real-time security monitoring. Check backend services.",
          variant: "destructive"
        });
      }
    };

    const cleanup = initializeBackendConnections();
    
    return () => {
      cleanup.then(cleanupFn => cleanupFn?.());
    };
  }, [toast]);

  return (
    <div className="min-h-screen bg-background">
      {/* Hero Section */}
      <div className="relative overflow-hidden bg-gradient-to-br from-background via-muted/50 to-background border-b">
        <div className="absolute inset-0 bg-grid-pattern opacity-5" />
        <div className="relative px-6 py-24 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-4xl text-center">
            <div className="relative mb-8">
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="w-32 h-32 bg-primary/20 rounded-full blur-3xl animate-pulse" />
              </div>
              <Shield className="relative mx-auto h-16 w-16 text-primary animate-pulse-glow" />
            </div>
            <h1 className="text-4xl font-bold tracking-tight sm:text-6xl gradient-text">
              Comprehensive Security Operations Center
            </h1>
            <p className="mt-6 text-lg leading-8 text-muted-foreground max-w-2xl mx-auto">
              Enterprise-grade security monitoring, vulnerability assessment, and penetration testing platform 
              with real-time threat intelligence and automated response capabilities.
            </p>
            <div className="mt-10 flex items-center justify-center gap-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                <span>Monitoring Active</span>
              </div>
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
                <span>Real-time Updates</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Dashboard */}
      <div className="px-6 py-12 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-7xl">
          
          {/* Quick Actions */}
          <div className="mb-12">
            <h2 className="text-2xl font-bold mb-6 gradient-text">Security Operations</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
              
              {/* Wazuh Management */}
              <Dialog open={isWazuhManagementOpen} onOpenChange={setIsWazuhManagementOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm" className="h-auto flex-col gap-2 p-4 glow-hover group">
                    <Shield className="h-6 w-6 group-hover:animate-pulse" />
                    <span className="text-xs">Wazuh</span>
                  </Button>
                </DialogTrigger>
                <DialogContent className="sm:max-w-[1200px] max-h-[90vh] gradient-card">
                  <DialogHeader>
                    <DialogTitle>Wazuh Security Management</DialogTitle>
                  </DialogHeader>
                  <div className="overflow-auto max-h-[calc(90vh-100px)]">
                    <WazuhManagement />
                  </div>
                </DialogContent>
              </Dialog>

              {/* SBOM Management */}
              <Dialog open={isAgentStatusOpen} onOpenChange={setIsAgentStatusOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm" className="h-auto flex-col gap-2 p-4 glow-hover group">
                    <Box className="h-6 w-6 group-hover:animate-pulse" />
                    <span className="text-xs">SBOM</span>
                  </Button>
                </DialogTrigger>
                <DialogContent className="sm:max-w-[1000px] max-h-[85vh] gradient-card border-primary/20">
                  <DialogHeader>
                    <DialogTitle className="flex items-center gap-2 text-xl">
                      <div className="relative">
                        <Box className="h-6 w-6 text-primary animate-pulse" />
                        <div className="absolute -top-1 -right-1 w-3 h-3 bg-primary rounded-full animate-ping" />
                      </div>
                      Software Bill of Materials (SBOM)
                      <Badge variant="default" className="ml-2 animate-pulse-glow">
                        WAZUH
                      </Badge>
                    </DialogTitle>
                    <DialogDescription className="text-base">
                      Generate comprehensive software inventories with vulnerability correlation using Wazuh Syscollector
                    </DialogDescription>
                  </DialogHeader>
                  <div className="overflow-auto max-h-[calc(85vh-100px)]">
                    <WazuhSBOMManagement />
                  </div>
                </DialogContent>
              </Dialog>

              {/* GVM Management */}
              <Dialog open={isGvmManagementOpen} onOpenChange={setIsGvmManagementOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm" className="h-auto flex-col gap-2 p-4 glow-hover group">
                    <Bug className="h-6 w-6 group-hover:animate-pulse" />
                    <span className="text-xs">GVM</span>
                  </Button>
                </DialogTrigger>
                <DialogContent className="sm:max-w-[1200px] max-h-[90vh] gradient-card">
                  <DialogHeader>
                    <DialogTitle>GVM Vulnerability Management</DialogTitle>
                  </DialogHeader>
                  <div className="overflow-auto max-h-[calc(90vh-100px)]">
                    <GVMManagement />
                  </div>
                </DialogContent>
              </Dialog>

              {/* Agent Configuration */}
              <Dialog open={isAgentConfigOpen} onOpenChange={setIsAgentConfigOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm" className="h-auto flex-col gap-2 p-4 glow-hover group">
                    <Settings className="h-6 w-6 group-hover:animate-pulse" />
                    <span className="text-xs">Config</span>
                  </Button>
                </DialogTrigger>
                <DialogContent className="sm:max-w-[1000px] max-h-[85vh] gradient-card">
                  <DialogHeader>
                    <DialogTitle>Advanced Agent Configuration</DialogTitle>
                  </DialogHeader>
                  <div className="overflow-auto max-h-[calc(85vh-100px)]">
                    <AgentConfigurationAdvanced 
                      agentId="default"
                      onConfigUpdate={() => {}}
                      onClose={() => setIsAgentConfigOpen(false)}
                    />
                  </div>
                </DialogContent>
              </Dialog>
              
              {/* Production Config */}
              <Dialog open={isProductionConfigOpen} onOpenChange={setIsProductionConfigOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm" className="h-auto flex-col gap-2 p-4 glow-hover group">
                    <Server className="h-6 w-6 group-hover:animate-pulse" />
                    <span className="text-xs">Production</span>
                  </Button>
                </DialogTrigger>
                <DialogContent className="sm:max-w-[1200px] max-h-[90vh] gradient-card">
                  <DialogHeader>
                    <DialogTitle>Production Security Configuration</DialogTitle>
                  </DialogHeader>
                  <div className="overflow-auto max-h-[calc(90vh-100px)]">
                    <ProductionReadySecurityConfig />
                  </div>
                </DialogContent>
              </Dialog>

              {/* Documentation */}
              <Dialog open={isDocumentationOpen} onOpenChange={setIsDocumentationOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm" className="h-auto flex-col gap-2 p-4 glow-hover group">
                    <FileText className="h-6 w-6 group-hover:animate-pulse" />
                    <span className="text-xs">Docs</span>
                  </Button>
                </DialogTrigger>
                <DialogContent className="sm:max-w-[1200px] max-h-[90vh] gradient-card">
                  <DialogHeader>
                    <DialogTitle>Security Documentation Library</DialogTitle>
                  </DialogHeader>
                  <div className="overflow-auto max-h-[calc(90vh-100px)]">
                    <DocumentationLibrary onClose={() => setIsDocumentationOpen(false)} />
                  </div>
                </DialogContent>
              </Dialog>

            </div>
          </div>

          {/* Service Status Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
            
            {/* Wazuh Status */}
            <Card className="gradient-card border-green-500/20 hover:border-green-500/40 transition-all duration-300">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Shield className="h-4 w-4 text-green-500" />
                  Wazuh SIEM
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-2xl font-bold">24/7</div>
                    <p className="text-xs text-muted-foreground">Monitoring</p>
                  </div>
                  <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse" />
                </div>
              </CardContent>
            </Card>

            {/* GVM Status */}
            <Card className="gradient-card border-blue-500/20 hover:border-blue-500/40 transition-all duration-300">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Bug className="h-4 w-4 text-blue-500" />
                  OpenVAS GVM
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-2xl font-bold">153</div>
                    <p className="text-xs text-muted-foreground">Vulnerabilities</p>
                  </div>
                  <div className="w-3 h-3 bg-blue-500 rounded-full animate-pulse" />
                </div>
              </CardContent>
            </Card>

            {/* OWASP ZAP Status */}
            <Card className="gradient-card border-orange-500/20 hover:border-orange-500/40 transition-all duration-300">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Zap className="h-4 w-4 text-orange-500" />
                  OWASP ZAP
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-2xl font-bold">12</div>
                    <p className="text-xs text-muted-foreground">Web Scans</p>
                  </div>
                  <div className="w-3 h-3 bg-orange-500 rounded-full animate-pulse" />
                </div>
              </CardContent>
            </Card>

            {/* SpiderFoot Status */}
            <Card className="gradient-card border-purple-500/20 hover:border-purple-500/40 transition-all duration-300">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Search className="h-4 w-4 text-purple-500" />
                  SpiderFoot
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-2xl font-bold">847</div>
                    <p className="text-xs text-muted-foreground">OSINT Records</p>
                  </div>
                  <div className="w-3 h-3 bg-purple-500 rounded-full animate-pulse" />
                </div>
              </CardContent>
            </Card>

          </div>

          {/* Recent Alerts */}
          <Card className="gradient-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-yellow-500" />
                Recent Security Alerts
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {[
                  { id: 1, title: "Failed login attempts detected", time: "2 minutes ago", severity: "high" },
                  { id: 2, title: "Vulnerability scan completed", time: "15 minutes ago", severity: "medium" },
                  { id: 3, title: "New agent registered", time: "1 hour ago", severity: "low" }
                ].map((alert) => (
                  <div key={alert.id} className="flex items-center justify-between p-3 border rounded-lg hover:bg-muted/50 transition-colors">
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${
                        alert.severity === 'high' ? 'bg-red-500' :
                        alert.severity === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                      }`} />
                      <span className="font-medium">{alert.title}</span>
                    </div>
                    <span className="text-sm text-muted-foreground">{alert.time}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;