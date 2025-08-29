import { Shield, Eye, Zap, Search, Activity, AlertTriangle, CheckCircle, Clock, Server, Database, Wifi, WifiOff, Users, Settings, Cog, FileText, ToggleLeft, ToggleRight, Scan, Bug, ShieldAlert, TrendingUp, Download, RefreshCw } from "lucide-react";
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
import { useToast } from "@/hooks/use-toast";
import SecurityChatbot from "./SecurityChatbot";
import { useSecurityStatus } from "@/hooks/useSecurityStatus";
import heroImage from "@/assets/security-hero.jpg";
import { useState } from "react";

const SecurityDashboard = () => {
  const { getConnectionIndicator } = useSecurityStatus();
  const [isAgentStatusOpen, setIsAgentStatusOpen] = useState(false);
  const [isAgentConfigOpen, setIsAgentConfigOpen] = useState(false);
  const [isCveAssessmentOpen, setIsCveAssessmentOpen] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<string>('001');
  const [cveScanning, setCveScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [agentConfig, setAgentConfig] = useState({
    logLevel: 'info',
    scanFrequency: '1h',
    enableSyscheck: true,
    enableRootcheck: true,
    enableOpenscap: false,
    enableSca: true,
    customRules: '',
    alertLevel: '7'
  });
  const { toast } = useToast();

  /**
   * Mock agent data with connection status indicators
   * In production, this would come from the Wazuh API
   */
  const agentData = [
    {
      id: "001",
      name: "web-server-01",
      ip: "192.168.1.10",
      os: "Ubuntu 20.04",
      status: "active",
      lastSeen: "2 min ago",
      version: "4.7.0",
      manager: "wazuh-manager-01",
      group: "web-servers"
    },
    {
      id: "002", 
      name: "db-server-01",
      ip: "192.168.1.11",
      os: "CentOS 8",
      status: "active",
      lastSeen: "5 min ago",
      version: "4.7.0",
      manager: "wazuh-manager-01",
      group: "database-servers"
    },
    {
      id: "003",
      name: "mail-server-01", 
      ip: "192.168.1.12",
      os: "Windows Server 2019",
      status: "disconnected",
      lastSeen: "2 hours ago",
      version: "4.6.2",
      manager: "wazuh-manager-01",
      group: "mail-servers"
    },
    {
      id: "004",
      name: "workstation-01",
      ip: "192.168.1.50",
      os: "Windows 11",
      status: "active",
      lastSeen: "1 min ago", 
      version: "4.7.0",
      manager: "wazuh-manager-02",
      group: "workstations"
    },
    {
      id: "005",
      name: "firewall-01",
      ip: "192.168.1.1",
      os: "pfSense 2.7",
      status: "never_connected",
      lastSeen: "Never",
      version: "N/A",
      manager: "wazuh-manager-01", 
      group: "network-devices"
    }
  ];

  /**
   * API connection status for different security services
   */
  const apiConnections = [
    {
      service: "Wazuh Manager",
      endpoint: "localhost:55000",
      status: "disconnected", // Based on network requests showing connection failures
      description: "SIEM agent management and log analysis"
    },
    {
      service: "OpenVAS Scanner",
      endpoint: "localhost:9392", 
      status: "disconnected", // Based on network requests showing connection failures
      description: "Vulnerability assessment and network scanning"
    },
    {
      service: "OWASP ZAP",
      endpoint: "localhost:8080",
      status: "disconnected", // Based on network requests showing connection failures  
      description: "Web application security testing"
    },
    {
      service: "Spiderfoot OSINT", 
      endpoint: "localhost:5001",
      status: "disconnected", // Based on network requests showing connection failures
      description: "Open source intelligence gathering"
    }
  ];

  /**
   * Handles saving agent configuration
   * In production, this would make API calls to update the Wazuh agent configuration
   */
  const handleSaveAgentConfig = () => {
    // In a real implementation, this would make an API call to the Wazuh manager
    // PUT /agents/{agent_id}/config with the configuration data
    toast({
      title: "Configuration Updated",
      description: `Agent ${selectedAgent} configuration has been updated successfully.`,
    });
    setIsAgentConfigOpen(false);
  };

  /**
   * Gets the selected agent data for configuration
   */
  const getSelectedAgentData = () => {
    return agentData.find(agent => agent.id === selectedAgent) || agentData[0];
  };

  /**
   * Mock CVE vulnerability data
   * In production, this would come from OpenVAS/GVM API and CVE databases
   */
  const cveVulnerabilities = [
    {
      id: "CVE-2023-44487",
      title: "HTTP/2 Rapid Reset Attack",
      severity: "HIGH",
      score: 7.5,
      description: "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly.",
      affected: ["nginx", "apache", "nodejs"],
      hosts: ["192.168.1.10", "192.168.1.11"],
      status: "open",
      published: "2023-10-10",
      solution: "Update to patched versions: nginx 1.25.2+, Apache 2.4.58+"
    },
    {
      id: "CVE-2023-4911",
      title: "Looney Tunables - glibc Buffer Overflow",
      severity: "CRITICAL",
      score: 9.8,
      description: "A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable.",
      affected: ["glibc"],
      hosts: ["192.168.1.10", "192.168.1.12"],
      status: "open",
      published: "2023-10-03",
      solution: "Update glibc to version 2.39 or apply security patches"
    },
    {
      id: "CVE-2023-38545",
      title: "curl SOCKS5 heap buffer overflow",
      severity: "HIGH",
      score: 8.8,
      description: "This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake.",
      affected: ["curl", "libcurl"],
      hosts: ["192.168.1.11"],
      status: "patched",
      published: "2023-10-11",
      solution: "Update curl to version 8.4.0 or later"
    },
    {
      id: "CVE-2023-22515",
      title: "Confluence Data Center Privilege Escalation",
      severity: "CRITICAL",
      score: 10.0,
      description: "Broken access control vulnerability in Confluence Data Center and Server allows an unauthenticated attacker to reset Confluence.",
      affected: ["atlassian-confluence"],
      hosts: ["192.168.1.15"],
      status: "open",
      published: "2023-10-04",
      solution: "Upgrade to fixed versions: 8.3.4, 8.4.4, 8.5.3, or later"
    },
    {
      id: "CVE-2023-34362",
      title: "MOVEit Transfer SQL Injection",
      severity: "CRITICAL",
      score: 9.8,
      description: "In Progress MOVEit Transfer before 2021.0.6, 2021.1.4, 2022.0.4, 2022.1.5, and 2023.0.1, a SQL injection vulnerability has been found.",
      affected: ["moveit-transfer"],
      hosts: ["192.168.1.20"],
      status: "mitigated",
      published: "2023-06-02",
      solution: "Upgrade MOVEit Transfer to the latest patched version"
    }
  ];

  /**
   * Handles starting a CVE assessment scan
   */
  const handleStartCveScan = () => {
    setCveScanning(true);
    setScanProgress(0);
    
    // Simulate scan progress
    const interval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setCveScanning(false);
          toast({
            title: "CVE Scan Complete",
            description: `Found ${cveVulnerabilities.length} vulnerabilities across ${new Set(cveVulnerabilities.flatMap(v => v.hosts)).size} hosts.`,
          });
          return 100;
        }
        return prev + Math.random() * 15;
      });
    }, 500);
  };

  /**
   * Gets vulnerability statistics
   */
  const getVulnStats = () => {
    const critical = cveVulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const high = cveVulnerabilities.filter(v => v.severity === 'HIGH').length;
    const medium = cveVulnerabilities.filter(v => v.severity === 'MEDIUM').length;
    const low = cveVulnerabilities.filter(v => v.severity === 'LOW').length;
    const open = cveVulnerabilities.filter(v => v.status === 'open').length;
    const patched = cveVulnerabilities.filter(v => v.status === 'patched').length;
    
    return { critical, high, medium, low, open, patched, total: cveVulnerabilities.length };
  };
  const tools = [
    {
      name: "Wazuh SIEM",
      description: "Security Information & Event Management",
      status: "active",
      agents: 42,
      alerts: 7,
      icon: Shield,
      color: "primary"
    },
    {
      name: "OpenVAS Scanner",
      description: "Vulnerability Assessment & NVT Scanning",
      status: "scanning",
      progress: 67,
      vulnerabilities: 23,
      icon: Eye,
      color: "secondary"
    },
    {
      name: "OWASP ZAP",
      description: "Web Application Security Testing",
      status: "active",
      scans: 5,
      findings: 12,
      icon: Zap,
      color: "accent"
    },
    {
      name: "Spiderfoot OSINT",
      description: "Open Source Intelligence Gathering",
      status: "monitoring",
      sources: 156,
      entities: 89,
      icon: Search,
      color: "primary"
    }
  ];

  const recentAlerts = [
    { type: "critical", message: "Suspicious network activity detected", time: "2m ago", source: "Wazuh" },
    { type: "warning", message: "High-risk vulnerability found in web server", time: "5m ago", source: "OpenVAS" },
    { type: "info", message: "OWASP scan completed successfully", time: "10m ago", source: "ZAP" },
    { type: "warning", message: "New threat intelligence indicators", time: "15m ago", source: "Spiderfoot" }
  ];

  return (
    <div className="min-h-screen gradient-bg text-foreground">
      {/* Hero Section */}
      <div className="relative overflow-hidden">
        <div 
          className="absolute inset-0 opacity-20"
          style={{
            backgroundImage: `url(${heroImage})`,
            backgroundSize: 'cover',
            backgroundPosition: 'center'
          }}
        />
        <div className="absolute inset-0 bg-gradient-to-r from-background/80 to-transparent" />
        
        <div className="relative container mx-auto px-6 py-16">
          <div className="max-w-4xl">
            <h1 className="text-6xl font-bold mb-6 text-glow animate-float">
              IPS Security Center
            </h1>
            <p className="text-xl text-muted-foreground mb-8">
              Unified cybersecurity monitoring with Wazuh, OpenVAS, OWASP ZAP, and Spiderfoot intelligence
            </p>
            
            {/* Security Administration Panel */}
            <Card className="gradient-card glow-hover mt-6">
              <CardHeader className="pb-2">
                <CardTitle className="text-xl text-glow">Security Administration</CardTitle>
                <CardDescription>Manage all security tools from one central location</CardDescription>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="siem" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="siem" className="flex items-center gap-2">
                      <Shield className="h-4 w-4" />
                      SIEM
                    </TabsTrigger>
                    <TabsTrigger value="vulnerability" className="flex items-center gap-2">
                      <Eye className="h-4 w-4" />
                      Vulnerability
                    </TabsTrigger>
                    <TabsTrigger value="webapp" className="flex items-center gap-2">
                      <Zap className="h-4 w-4" />
                      Web App
                    </TabsTrigger>
                    <TabsTrigger value="osint" className="flex items-center gap-2">
                      <Search className="h-4 w-4" />
                      OSINT
                    </TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="siem" className="mt-4">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <Button 
                        className="glow-hover" 
                        variant="default"
                        size="sm"
                        onClick={() => window.location.href = '/wazuh'}
                      >
                        Manage Wazuh SIEM
                      </Button>
                      <Dialog open={isAgentStatusOpen} onOpenChange={setIsAgentStatusOpen}>
                        <DialogTrigger asChild>
                          <Button variant="outline" size="sm" className="glow-hover group">
                            <Users className="h-4 w-4 mr-2 group-hover:animate-pulse" />
                            View Agent Status
                            <div className="ml-2 w-2 h-2 rounded-full bg-primary animate-pulse-glow" />
                          </Button>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-[1000px] max-h-[85vh] gradient-card border-primary/20">
                          <DialogHeader>
                            <DialogTitle className="flex items-center gap-2 text-xl">
                              <div className="relative">
                                <Server className="h-6 w-6 text-primary animate-pulse" />
                                <div className="absolute -top-1 -right-1 w-3 h-3 bg-primary rounded-full animate-ping" />
                              </div>
                              Security Agent Status Dashboard
                              <Badge variant="default" className="ml-2 animate-pulse-glow">
                                LIVE
                              </Badge>
                            </DialogTitle>
                            <DialogDescription className="text-base">
                              Real-time monitoring of security agents and API connections across your infrastructure
                            </DialogDescription>
                          </DialogHeader>

                          <div className="space-y-6">
                            {/* Enhanced API Connection Status with Visual Indicators */}
                            <div className="space-y-4">
                              <div className="flex items-center justify-between">
                                <h3 className="text-lg font-semibold flex items-center gap-2">
                                  <div className="relative">
                                    <Wifi className="h-5 w-5 text-primary" />
                                    <div className="absolute inset-0 w-5 h-5 border-2 border-primary rounded-full animate-ping opacity-20" />
                                  </div>
                                  API Connection Status
                                </h3>
                                <div className="flex items-center gap-2">
                                  <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                                  <span className="text-sm text-muted-foreground">All services offline</span>
                                </div>
                              </div>
                              
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {apiConnections.map((connection, index) => (
                                  <Card key={connection.service} className="gradient-card border hover:border-primary/50 transition-all duration-300 group">
                                    <CardContent className="p-4">
                                      <div className="flex items-center justify-between mb-3">
                                        <div className="flex items-center gap-3">
                                          <div className="relative">
                                            <div className={`w-4 h-4 rounded-full ${
                                              connection.status === 'connected' 
                                                ? 'bg-green-500 shadow-lg shadow-green-500/50' 
                                                : 'bg-red-500 shadow-lg shadow-red-500/50'
                                            } animate-pulse`} />
                                            <div className={`absolute inset-0 w-4 h-4 rounded-full ${
                                              connection.status === 'connected' 
                                                ? 'border-2 border-green-500 animate-ping' 
                                                : 'border-2 border-red-500 animate-ping'
                                            } opacity-30`} />
                                          </div>
                                          <div>
                                            <span className="font-semibold text-sm group-hover:text-primary transition-colors">
                                              {connection.service}
                                            </span>
                                            <div className="flex items-center gap-1 mt-1">
                                              <Badge 
                                                variant={connection.status === 'connected' ? 'default' : 'destructive'}
                                                className="text-xs animate-pulse-glow"
                                              >
                                                {connection.status === 'connected' ? 'ONLINE' : 'OFFLINE'}
                                              </Badge>
                                              <span className="text-xs text-muted-foreground font-mono">
                                                {connection.endpoint}
                                              </span>
                                            </div>
                                          </div>
                                        </div>
                                        <div className={`p-2 rounded-full ${
                                          connection.status === 'connected' 
                                            ? 'bg-green-500/10 text-green-500' 
                                            : 'bg-red-500/10 text-red-500'
                                        }`}>
                                          {connection.status === 'connected' ? (
                                            <CheckCircle className="h-4 w-4" />
                                          ) : (
                                            <WifiOff className="h-4 w-4" />
                                          )}
                                        </div>
                                      </div>
                                      <p className="text-xs text-muted-foreground">{connection.description}</p>
                                      
                                      {/* Connection Progress Bar */}
                                      <div className="mt-3">
                                        <div className="flex justify-between text-xs mb-1">
                                          <span>Connection Health</span>
                                          <span>{connection.status === 'connected' ? '100%' : '0%'}</span>
                                        </div>
                                        <Progress 
                                          value={connection.status === 'connected' ? 100 : 0} 
                                          className={`h-2 ${connection.status === 'connected' ? 'glow' : ''}`}
                                        />
                                      </div>
                                    </CardContent>
                                  </Card>
                                ))}
                              </div>
                            </div>

                            {/* Enhanced Agent Status with Interactive Elements */}
                            <div className="space-y-4">
                              <div className="flex items-center justify-between">
                                <h3 className="text-lg font-semibold flex items-center gap-2">
                                  <div className="relative">
                                    <Server className="h-5 w-5 text-primary animate-pulse" />
                                    <div className="absolute -top-1 -right-1 w-3 h-3 bg-accent rounded-full animate-bounce" />
                                  </div>
                                  Wazuh Agents
                                  <Badge variant="outline" className="text-xs">
                                    {agentData.length} Total
                                  </Badge>
                                </h3>
                                
                                {/* Real-time Status Indicators */}
                                <div className="flex gap-3 text-sm">
                                  <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-green-500/10 border border-green-500/20">
                                    <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse-glow" />
                                    <span className="text-green-400 font-medium">
                                      {agentData.filter(a => a.status === 'active').length} Active
                                    </span>
                                  </div>
                                  <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/20">
                                    <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                                    <span className="text-red-400 font-medium">
                                      {agentData.filter(a => a.status === 'disconnected').length} Offline
                                    </span>
                                  </div>
                                  <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-yellow-500/10 border border-yellow-500/20">
                                    <div className="w-2 h-2 rounded-full bg-yellow-500 animate-pulse" />
                                    <span className="text-yellow-400 font-medium">
                                      {agentData.filter(a => a.status === 'never_connected').length} Pending
                                    </span>
                                  </div>
                                </div>
                              </div>

                              {/* Enhanced Agent Table */}
                              <Card className="gradient-card border border-primary/20 overflow-hidden">
                                <ScrollArea className="h-[400px]">
                                  <Table>
                                    <TableHeader>
                                      <TableRow className="border-border/50">
                                        <TableHead className="font-semibold">Status</TableHead>
                                        <TableHead className="font-semibold">Agent ID</TableHead>
                                        <TableHead className="font-semibold">Name</TableHead>
                                        <TableHead className="font-semibold">IP Address</TableHead>
                                        <TableHead className="font-semibold">OS</TableHead>
                                        <TableHead className="font-semibold">Last Seen</TableHead>
                                        <TableHead className="font-semibold">Version</TableHead>
                                        <TableHead className="font-semibold">Group</TableHead>
                                      </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                      {agentData.map((agent, index) => (
                                        <TableRow key={agent.id} className="hover:bg-primary/5 transition-colors group">
                                          <TableCell>
                                            <div className="flex items-center gap-2">
                                              <div className="relative">
                                                <div className={`w-3 h-3 rounded-full ${
                                                  agent.status === 'active' 
                                                    ? 'bg-green-500 shadow-lg shadow-green-500/50' 
                                                    : agent.status === 'disconnected'
                                                    ? 'bg-red-500 shadow-lg shadow-red-500/50'
                                                    : 'bg-yellow-500 shadow-lg shadow-yellow-500/50'
                                                } animate-pulse`} />
                                                <div className={`absolute inset-0 w-3 h-3 rounded-full ${
                                                  agent.status === 'active' 
                                                    ? 'border-2 border-green-500 animate-ping' 
                                                    : agent.status === 'disconnected'
                                                    ? 'border-2 border-red-500 animate-ping'
                                                    : 'border-2 border-yellow-500 animate-ping'
                                                } opacity-20`} />
                                              </div>
                                            </div>
                                          </TableCell>
                                          <TableCell className="font-mono text-sm font-semibold text-primary group-hover:text-accent transition-colors">
                                            {agent.id}
                                          </TableCell>
                                          <TableCell className="font-medium group-hover:text-foreground transition-colors">
                                            {agent.name}
                                          </TableCell>
                                          <TableCell className="font-mono text-sm">{agent.ip}</TableCell>
                                          <TableCell className="text-sm">{agent.os}</TableCell>
                                          <TableCell className="text-sm">
                                            <div className="flex items-center gap-1">
                                              <Clock className="h-3 w-3 text-muted-foreground" />
                                              {agent.lastSeen}
                                            </div>
                                          </TableCell>
                                          <TableCell>
                                            <Badge variant="outline" className="font-mono text-xs">
                                              {agent.version}
                                            </Badge>
                                          </TableCell>
                                          <TableCell>
                                            <Badge variant="secondary" className="text-xs">
                                              {agent.group}
                                            </Badge>
                                          </TableCell>
                                        </TableRow>
                                      ))}
                                    </TableBody>
                                  </Table>
                                </ScrollArea>
                              </Card>
                            </div>

                            {/* Enhanced Statistics Dashboard */}
                            <Card className="gradient-card border border-primary/20 bg-gradient-to-r from-primary/5 to-accent/5">
                              <CardContent className="p-6">
                                <h4 className="text-lg font-semibold mb-4 flex items-center gap-2">
                                  <Activity className="h-5 w-5 text-primary animate-pulse" />
                                  Real-time Infrastructure Health
                                </h4>
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                                  <div className="text-center group cursor-pointer">
                                    <div className="relative mb-2">
                                      <div className="text-3xl font-bold text-green-500 group-hover:scale-110 transition-transform">
                                        {agentData.filter(a => a.status === 'active').length}
                                      </div>
                                      <div className="absolute inset-0 bg-green-500/20 rounded-full animate-pulse opacity-0 group-hover:opacity-100 transition-opacity" />
                                    </div>
                                    <div className="text-sm text-muted-foreground">Active Agents</div>
                                    <Progress value={75} className="mt-2 h-2 glow" />
                                  </div>
                                  
                                  <div className="text-center group cursor-pointer">
                                    <div className="relative mb-2">
                                      <div className="text-3xl font-bold text-red-500 group-hover:scale-110 transition-transform">
                                        {agentData.filter(a => a.status === 'disconnected').length}
                                      </div>
                                      <div className="absolute inset-0 bg-red-500/20 rounded-full animate-pulse opacity-0 group-hover:opacity-100 transition-opacity" />
                                    </div>
                                    <div className="text-sm text-muted-foreground">Disconnected</div>
                                    <Progress value={20} className="mt-2 h-2" />
                                  </div>
                                  
                                  <div className="text-center group cursor-pointer">
                                    <div className="relative mb-2">
                                      <div className="text-3xl font-bold text-yellow-500 group-hover:scale-110 transition-transform">
                                        {agentData.filter(a => a.status === 'never_connected').length}
                                      </div>
                                      <div className="absolute inset-0 bg-yellow-500/20 rounded-full animate-pulse opacity-0 group-hover:opacity-100 transition-opacity" />
                                    </div>
                                    <div className="text-sm text-muted-foreground">Never Connected</div>
                                    <Progress value={5} className="mt-2 h-2" />
                                  </div>
                                  
                                  <div className="text-center group cursor-pointer">
                                    <div className="relative mb-2">
                                      <div className="text-3xl font-bold text-primary group-hover:scale-110 transition-transform">
                                        {apiConnections.filter(c => c.status === 'connected').length}/{apiConnections.length}
                                      </div>
                                      <div className="absolute inset-0 bg-primary/20 rounded-full animate-pulse opacity-0 group-hover:opacity-100 transition-opacity" />
                                    </div>
                                    <div className="text-sm text-muted-foreground">APIs Online</div>
                                    <Progress value={0} className="mt-2 h-2" />
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          </div>

                          <div className="flex justify-between items-center gap-2 pt-6 border-t border-border/50">
                            <div className="flex items-center gap-2 text-sm text-muted-foreground">
                              <div className="w-2 h-2 rounded-full bg-primary animate-pulse-glow" />
                              <span>Auto-refresh every 30s</span>
                            </div>
                            <div className="flex gap-2">
                              <Button variant="outline" onClick={() => setIsAgentStatusOpen(false)} className="glow-hover">
                                Close Dashboard
                              </Button>
                              <Button className="glow-hover group">
                                <Settings className="h-4 w-4 mr-2 group-hover:animate-spin" />
                                Manage All Agents
                              </Button>
                            </div>
                          </div>
                        </DialogContent>
                      </Dialog>
                      
                      <Dialog open={isAgentConfigOpen} onOpenChange={setIsAgentConfigOpen}>
                        <DialogTrigger asChild>
                          <Button variant="outline" size="sm" className="glow-hover">
                            <Cog className="h-4 w-4 mr-2" />
                            Agent Configuration
                          </Button>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-[700px] max-h-[80vh] overflow-y-auto gradient-card">
                          <DialogHeader>
                            <DialogTitle className="flex items-center gap-2">
                              <Settings className="h-5 w-5 text-primary" />
                              Security Agent Configuration
                            </DialogTitle>
                            <DialogDescription>
                              Configure monitoring settings and security policies for Wazuh agents
                            </DialogDescription>
                          </DialogHeader>

                          <div className="space-y-6 py-4">
                            {/* Agent Selection */}
                            <div className="space-y-3">
                              <Label htmlFor="agent-select">Select Agent to Configure</Label>
                              <Select value={selectedAgent} onValueChange={setSelectedAgent}>
                                <SelectTrigger className="glow-hover">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent className="bg-popover border border-border z-50">
                                  {agentData.map((agent) => (
                                    <SelectItem key={agent.id} value={agent.id}>
                                      <div className="flex items-center gap-2">
                                        <div className={`w-2 h-2 rounded-full ${
                                          agent.status === 'active' 
                                            ? 'bg-green-500' 
                                            : agent.status === 'disconnected'
                                            ? 'bg-red-500'
                                            : 'bg-yellow-500'
                                        }`} />
                                        <span className="font-mono text-sm">{agent.id}</span>
                                        <span>{agent.name}</span>
                                        <span className="text-muted-foreground">({agent.ip})</span>
                                      </div>
                                    </SelectItem>
                                  ))}
                                </SelectContent>
                              </Select>
                              
                              {/* Selected Agent Info */}
                              <Card className="gradient-card border">
                                <CardContent className="p-4">
                                  <div className="grid grid-cols-2 gap-4 text-sm">
                                    <div>
                                      <span className="text-muted-foreground">Agent:</span>
                                      <span className="ml-2 font-medium">{getSelectedAgentData()?.name}</span>
                                    </div>
                                    <div>
                                      <span className="text-muted-foreground">IP:</span>
                                      <span className="ml-2 font-mono">{getSelectedAgentData()?.ip}</span>
                                    </div>
                                    <div>
                                      <span className="text-muted-foreground">OS:</span>
                                      <span className="ml-2">{getSelectedAgentData()?.os}</span>
                                    </div>
                                    <div>
                                      <span className="text-muted-foreground">Group:</span>
                                      <Badge variant="outline" className="ml-2 text-xs">
                                        {getSelectedAgentData()?.group}
                                      </Badge>
                                    </div>
                                  </div>
                                </CardContent>
                              </Card>
                            </div>

                            {/* Configuration Tabs */}
                            <Tabs defaultValue="general" className="space-y-4">
                              <TabsList className="grid w-full grid-cols-3">
                                <TabsTrigger value="general">General Settings</TabsTrigger>
                                <TabsTrigger value="monitoring">Monitoring Modules</TabsTrigger>
                                <TabsTrigger value="custom">Custom Rules</TabsTrigger>
                              </TabsList>

                              <TabsContent value="general" className="space-y-4">
                                <div className="grid grid-cols-2 gap-4">
                                  <div className="space-y-2">
                                    <Label htmlFor="log-level">Log Level</Label>
                                    <Select value={agentConfig.logLevel} onValueChange={(value) => setAgentConfig({...agentConfig, logLevel: value})}>
                                      <SelectTrigger className="glow-hover">
                                        <SelectValue />
                                      </SelectTrigger>
                                      <SelectContent className="bg-popover border border-border z-50">
                                        <SelectItem value="debug">Debug (Most Verbose)</SelectItem>
                                        <SelectItem value="info">Info (Recommended)</SelectItem>
                                        <SelectItem value="warning">Warning</SelectItem>
                                        <SelectItem value="error">Error (Least Verbose)</SelectItem>
                                      </SelectContent>
                                    </Select>
                                  </div>
                                  
                                  <div className="space-y-2">
                                    <Label htmlFor="scan-frequency">Scan Frequency</Label>
                                    <Select value={agentConfig.scanFrequency} onValueChange={(value) => setAgentConfig({...agentConfig, scanFrequency: value})}>
                                      <SelectTrigger className="glow-hover">
                                        <SelectValue />
                                      </SelectTrigger>
                                      <SelectContent className="bg-popover border border-border z-50">
                                        <SelectItem value="15m">Every 15 minutes</SelectItem>
                                        <SelectItem value="30m">Every 30 minutes</SelectItem>
                                        <SelectItem value="1h">Every hour (Recommended)</SelectItem>
                                        <SelectItem value="6h">Every 6 hours</SelectItem>
                                        <SelectItem value="12h">Every 12 hours</SelectItem>
                                        <SelectItem value="24h">Daily</SelectItem>
                                      </SelectContent>
                                    </Select>
                                  </div>
                                </div>

                                <div className="space-y-2">
                                  <Label htmlFor="alert-level">Minimum Alert Level</Label>
                                  <Select value={agentConfig.alertLevel} onValueChange={(value) => setAgentConfig({...agentConfig, alertLevel: value})}>
                                    <SelectTrigger className="glow-hover">
                                      <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent className="bg-popover border border-border z-50">
                                      <SelectItem value="1">Level 1+ (All Events)</SelectItem>
                                      <SelectItem value="3">Level 3+ (Successful Events)</SelectItem>
                                      <SelectItem value="5">Level 5+ (Low Priority)</SelectItem>
                                      <SelectItem value="7">Level 7+ (Medium Priority) - Recommended</SelectItem>
                                      <SelectItem value="10">Level 10+ (High Priority)</SelectItem>
                                      <SelectItem value="12">Level 12+ (Critical Only)</SelectItem>
                                    </SelectContent>
                                  </Select>
                                </div>
                              </TabsContent>

                              <TabsContent value="monitoring" className="space-y-4">
                                <div className="space-y-4">
                                  <div className="flex items-center justify-between">
                                    <div className="space-y-0.5">
                                      <Label className="text-base">File Integrity Monitoring (Syscheck)</Label>
                                      <p className="text-sm text-muted-foreground">Monitor file system changes and integrity</p>
                                    </div>
                                    <Switch 
                                      checked={agentConfig.enableSyscheck} 
                                      onCheckedChange={(checked) => setAgentConfig({...agentConfig, enableSyscheck: checked})}
                                    />
                                  </div>

                                  <div className="flex items-center justify-between">
                                    <div className="space-y-0.5">
                                      <Label className="text-base">Rootkit Detection (Rootcheck)</Label>
                                      <p className="text-sm text-muted-foreground">Detect rootkits and system anomalies</p>
                                    </div>
                                    <Switch 
                                      checked={agentConfig.enableRootcheck} 
                                      onCheckedChange={(checked) => setAgentConfig({...agentConfig, enableRootcheck: checked})}
                                    />
                                  </div>

                                  <div className="flex items-center justify-between">
                                    <div className="space-y-0.5">
                                      <Label className="text-base">OpenSCAP Integration</Label>
                                      <p className="text-sm text-muted-foreground">Security compliance and vulnerability assessment</p>
                                    </div>
                                    <Switch 
                                      checked={agentConfig.enableOpenscap} 
                                      onCheckedChange={(checked) => setAgentConfig({...agentConfig, enableOpenscap: checked})}
                                    />
                                  </div>

                                  <div className="flex items-center justify-between">
                                    <div className="space-y-0.5">
                                      <Label className="text-base">Security Configuration Assessment (SCA)</Label>
                                      <p className="text-sm text-muted-foreground">Automated security policy compliance checks</p>
                                    </div>
                                    <Switch 
                                      checked={agentConfig.enableSca} 
                                      onCheckedChange={(checked) => setAgentConfig({...agentConfig, enableSca: checked})}
                                    />
                                  </div>
                                </div>
                              </TabsContent>

                              <TabsContent value="custom" className="space-y-4">
                                <div className="space-y-2">
                                  <Label htmlFor="custom-rules">Custom Detection Rules</Label>
                                  <Textarea
                                    id="custom-rules"
                                    placeholder={`<!-- Add custom local rules for this agent -->
<group name="local">
  <rule id="100001" level="7">
    <match>custom_pattern</match>
    <description>Custom rule for agent ${selectedAgent}</description>
  </rule>
</group>`}
                                    value={agentConfig.customRules}
                                    onChange={(e) => setAgentConfig({...agentConfig, customRules: e.target.value})}
                                    className="glow-hover font-mono text-sm min-h-[200px]"
                                  />
                                  <p className="text-xs text-muted-foreground">
                                    Define custom rules specific to this agent. Rules will be applied locally on the agent.
                                  </p>
                                </div>

                                <Card className="gradient-card border">
                                  <CardContent className="p-4">
                                    <h4 className="text-sm font-semibold mb-2">Configuration Preview</h4>
                                    <div className="space-y-1 text-xs font-mono bg-muted/50 p-3 rounded max-h-[150px] overflow-y-auto">
                                      <div>Log Level: {agentConfig.logLevel}</div>
                                      <div>Scan Frequency: {agentConfig.scanFrequency}</div>
                                      <div>Alert Level: {agentConfig.alertLevel}+</div>
                                      <div>Syscheck: {agentConfig.enableSyscheck ? 'Enabled' : 'Disabled'}</div>
                                      <div>Rootcheck: {agentConfig.enableRootcheck ? 'Enabled' : 'Disabled'}</div>
                                      <div>OpenSCAP: {agentConfig.enableOpenscap ? 'Enabled' : 'Disabled'}</div>
                                      <div>SCA: {agentConfig.enableSca ? 'Enabled' : 'Disabled'}</div>
                                      {agentConfig.customRules && <div>Custom Rules: {agentConfig.customRules.split('\n').length} lines</div>}
                                    </div>
                                  </CardContent>
                                </Card>
                              </TabsContent>
                            </Tabs>
                          </div>

                          <div className="flex justify-end gap-2 pt-4">
                            <Button variant="outline" onClick={() => setIsAgentConfigOpen(false)}>
                              Cancel
                            </Button>
                            <Button onClick={handleSaveAgentConfig} className="glow-hover">
                              <Settings className="h-4 w-4 mr-2" />
                              Save Configuration
                            </Button>
                          </div>
                        </DialogContent>
                      </Dialog>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="vulnerability" className="mt-4">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <Button 
                        className="glow-hover" 
                        variant="default"
                        size="sm"
                        onClick={() => window.location.href = '/gvm'}
                      >
                        Manage GVM/OpenVAS
                      </Button>
                      
                      <Dialog open={isCveAssessmentOpen} onOpenChange={setIsCveAssessmentOpen}>
                        <DialogTrigger asChild>
                          <Button variant="outline" size="sm" className="glow-hover group">
                            <Bug className="h-4 w-4 mr-2 group-hover:animate-bounce" />
                            CVE Assessment
                            <div className="ml-2 w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                          </Button>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-[1100px] max-h-[90vh] gradient-card border-primary/20">
                          <DialogHeader>
                            <DialogTitle className="flex items-center gap-2 text-xl">
                              <div className="relative">
                                <ShieldAlert className="h-6 w-6 text-red-500 animate-pulse" />
                                <div className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full animate-ping" />
                              </div>
                              CVE Vulnerability Assessment
                              <Badge variant="destructive" className="ml-2 animate-pulse-glow">
                                {getVulnStats().critical + getVulnStats().high} HIGH RISK
                              </Badge>
                            </DialogTitle>
                            <DialogDescription className="text-base">
                              Comprehensive vulnerability assessment using CVE database and OpenVAS scanning
                            </DialogDescription>
                          </DialogHeader>

                          <div className="space-y-6">
                            {/* Scan Controls and Statistics */}
                            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                              {/* Scan Control Panel */}
                              <Card className="lg:col-span-1 gradient-card border border-primary/20">
                                <CardHeader className="pb-3">
                                  <CardTitle className="text-lg flex items-center gap-2">
                                    <Scan className="h-5 w-5 text-primary animate-pulse" />
                                    Vulnerability Scan
                                  </CardTitle>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                  <Button 
                                    onClick={handleStartCveScan}
                                    disabled={cveScanning}
                                    className="w-full glow-hover group"
                                    variant={cveScanning ? "secondary" : "default"}
                                  >
                                    {cveScanning ? (
                                      <>
                                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                                        Scanning...
                                      </>
                                    ) : (
                                      <>
                                        <Scan className="h-4 w-4 mr-2 group-hover:animate-bounce" />
                                        Start CVE Scan
                                      </>
                                    )}
                                  </Button>
                                  
                                  {cveScanning && (
                                    <div className="space-y-2">
                                      <div className="flex justify-between text-sm">
                                        <span>Scan Progress</span>
                                        <span>{Math.round(scanProgress)}%</span>
                                      </div>
                                      <Progress value={scanProgress} className="glow animate-pulse" />
                                      <p className="text-xs text-muted-foreground">
                                        Analyzing {agentData.length} hosts for vulnerabilities...
                                      </p>
                                    </div>
                                  )}
                                  
                                  <div className="pt-2 border-t border-border/50">
                                    <div className="text-sm text-muted-foreground mb-2">Last Scan</div>
                                    <div className="text-sm font-medium">2 hours ago</div>
                                    <div className="text-xs text-muted-foreground">Coverage: All hosts</div>
                                  </div>
                                </CardContent>
                              </Card>

                              {/* Vulnerability Statistics */}
                              <Card className="lg:col-span-2 gradient-card border border-red-500/20 bg-gradient-to-br from-red-500/5 to-orange-500/5">
                                <CardHeader className="pb-3">
                                  <CardTitle className="text-lg flex items-center gap-2">
                                    <TrendingUp className="h-5 w-5 text-red-500 animate-pulse" />
                                    Vulnerability Overview
                                  </CardTitle>
                                </CardHeader>
                                <CardContent>
                                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                    <div className="text-center group cursor-pointer hover-scale">
                                      <div className="relative mb-2">
                                        <div className="text-3xl font-bold text-red-500 group-hover:scale-110 transition-transform animate-pulse">
                                          {getVulnStats().critical}
                                        </div>
                                        <div className="absolute inset-0 bg-red-500/20 rounded-full animate-pulse opacity-0 group-hover:opacity-100 transition-opacity" />
                                      </div>
                                      <div className="text-sm font-medium text-red-400">Critical</div>
                                      <div className="text-xs text-muted-foreground">Score 9.0+</div>
                                    </div>
                                    
                                    <div className="text-center group cursor-pointer hover-scale">
                                      <div className="relative mb-2">
                                        <div className="text-3xl font-bold text-orange-500 group-hover:scale-110 transition-transform">
                                          {getVulnStats().high}
                                        </div>
                                        <div className="absolute inset-0 bg-orange-500/20 rounded-full animate-pulse opacity-0 group-hover:opacity-100 transition-opacity" />
                                      </div>
                                      <div className="text-sm font-medium text-orange-400">High</div>
                                      <div className="text-xs text-muted-foreground">Score 7.0-8.9</div>
                                    </div>
                                    
                                    <div className="text-center group cursor-pointer hover-scale">
                                      <div className="relative mb-2">
                                        <div className="text-3xl font-bold text-yellow-500 group-hover:scale-110 transition-transform">
                                          {getVulnStats().medium}
                                        </div>
                                        <div className="absolute inset-0 bg-yellow-500/20 rounded-full animate-pulse opacity-0 group-hover:opacity-100 transition-opacity" />
                                      </div>
                                      <div className="text-sm font-medium text-yellow-400">Medium</div>
                                      <div className="text-xs text-muted-foreground">Score 4.0-6.9</div>
                                    </div>
                                    
                                    <div className="text-center group cursor-pointer hover-scale">
                                      <div className="relative mb-2">
                                        <div className="text-3xl font-bold text-green-500 group-hover:scale-110 transition-transform">
                                          {getVulnStats().patched}
                                        </div>
                                        <div className="absolute inset-0 bg-green-500/20 rounded-full animate-pulse opacity-0 group-hover:opacity-100 transition-opacity" />
                                      </div>
                                      <div className="text-sm font-medium text-green-400">Patched</div>
                                      <div className="text-xs text-muted-foreground">Remediated</div>
                                    </div>
                                  </div>
                                </CardContent>
                              </Card>
                            </div>

                            {/* Vulnerability Details Table */}
                            <Card className="gradient-card border border-red-500/20">
                              <CardHeader className="pb-3">
                                <div className="flex items-center justify-between">
                                  <CardTitle className="text-lg flex items-center gap-2">
                                    <AlertTriangle className="h-5 w-5 text-red-500 animate-pulse" />
                                    Detected Vulnerabilities
                                    <Badge variant="outline" className="text-xs">
                                      {getVulnStats().total} Total
                                    </Badge>
                                  </CardTitle>
                                  <Button variant="outline" size="sm" className="glow-hover">
                                    <Download className="h-4 w-4 mr-2" />
                                    Export Report
                                  </Button>
                                </div>
                              </CardHeader>
                              <CardContent>
                                <ScrollArea className="h-[400px] rounded-md border">
                                  <Table>
                                    <TableHeader>
                                      <TableRow className="border-border/50">
                                        <TableHead className="font-semibold">CVE ID</TableHead>
                                        <TableHead className="font-semibold">Severity</TableHead>
                                        <TableHead className="font-semibold">Title</TableHead>
                                        <TableHead className="font-semibold">Affected Hosts</TableHead>
                                        <TableHead className="font-semibold">Status</TableHead>
                                        <TableHead className="font-semibold">CVSS Score</TableHead>
                                        <TableHead className="font-semibold">Published</TableHead>
                                      </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                      {cveVulnerabilities.map((vuln, index) => (
                                        <TableRow key={vuln.id} className="hover:bg-primary/5 transition-colors group animate-fade-in" style={{animationDelay: `${index * 0.1}s`}}>
                                          <TableCell className="font-mono text-sm font-semibold text-primary group-hover:text-accent transition-colors">
                                            {vuln.id}
                                          </TableCell>
                                          <TableCell>
                                            <div className="flex items-center gap-2">
                                              <div className={`w-3 h-3 rounded-full ${
                                                vuln.severity === 'CRITICAL' 
                                                  ? 'bg-red-500 shadow-lg shadow-red-500/50 animate-pulse' 
                                                  : vuln.severity === 'HIGH'
                                                  ? 'bg-orange-500 shadow-lg shadow-orange-500/50 animate-pulse'
                                                  : vuln.severity === 'MEDIUM'
                                                  ? 'bg-yellow-500 shadow-lg shadow-yellow-500/50'
                                                  : 'bg-blue-500 shadow-lg shadow-blue-500/50'
                                              }`} />
                                              <Badge 
                                                variant={
                                                  vuln.severity === 'CRITICAL' ? 'destructive' : 
                                                  vuln.severity === 'HIGH' ? 'destructive' : 'secondary'
                                                }
                                                className="text-xs animate-pulse-glow"
                                              >
                                                {vuln.severity}
                                              </Badge>
                                            </div>
                                          </TableCell>
                                          <TableCell className="max-w-[300px]">
                                            <div className="font-medium group-hover:text-foreground transition-colors">
                                              {vuln.title}
                                            </div>
                                            <div className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                              {vuln.description}
                                            </div>
                                          </TableCell>
                                          <TableCell>
                                            <div className="space-y-1">
                                              {vuln.hosts.map((host, i) => (
                                                <Badge key={i} variant="outline" className="text-xs font-mono">
                                                  {host}
                                                </Badge>
                                              ))}
                                            </div>
                                          </TableCell>
                                          <TableCell>
                                            <Badge 
                                              variant={vuln.status === 'open' ? 'destructive' : vuln.status === 'patched' ? 'default' : 'secondary'}
                                              className="text-xs"
                                            >
                                              {vuln.status.toUpperCase()}
                                            </Badge>
                                          </TableCell>
                                          <TableCell>
                                            <div className={`font-bold text-sm ${
                                              vuln.score >= 9 ? 'text-red-500' :
                                              vuln.score >= 7 ? 'text-orange-500' :
                                              vuln.score >= 4 ? 'text-yellow-500' : 'text-blue-500'
                                            }`}>
                                              {vuln.score}/10
                                            </div>
                                          </TableCell>
                                          <TableCell className="text-sm">
                                            {vuln.published}
                                          </TableCell>
                                        </TableRow>
                                      ))}
                                    </TableBody>
                                  </Table>
                                </ScrollArea>
                              </CardContent>
                            </Card>
                          </div>

                          <div className="flex justify-between items-center gap-2 pt-6 border-t border-border/50">
                            <div className="flex items-center gap-2 text-sm text-muted-foreground">
                              <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse-glow" />
                              <span>Real-time CVE monitoring active</span>
                            </div>
                            <div className="flex gap-2">
                              <Button variant="outline" onClick={() => setIsCveAssessmentOpen(false)} className="glow-hover">
                                Close Assessment
                              </Button>
                              <Button className="glow-hover group">
                                <ShieldAlert className="h-4 w-4 mr-2 group-hover:animate-bounce" />
                                Generate Report
                              </Button>
                            </div>
                          </div>
                        </DialogContent>
                      </Dialog>
                      <Button variant="outline" size="sm">
                        Scan Results
                      </Button>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="webapp" className="mt-4">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <Button className="glow-hover" variant="default" size="sm">
                        OWASP Top 10 Scan
                      </Button>
                      <Button variant="outline" size="sm">
                        Custom ZAP Scan
                      </Button>
                      <Button variant="outline" size="sm">
                        Penetration Testing
                      </Button>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="osint" className="mt-4">
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <Button className="glow-hover" variant="default" size="sm">
                        Spiderfoot OSINT
                      </Button>
                      <Button variant="outline" size="sm">
                        Intelligence Gathering
                      </Button>
                      <Button variant="outline" size="sm">
                        Threat Analysis
                      </Button>
                    </div>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>

      {/* Dashboard Grid */}
      <div className="container mx-auto px-6 py-12">
        {/* Status Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
          {tools.map((tool, index) => (
            <Card key={tool.name} className="gradient-card glow-hover animate-pulse-glow">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <tool.icon className={`h-8 w-8 text-${tool.color}`} />
                  <Badge 
                    variant={tool.status === 'active' ? 'default' : 'secondary'}
                    className="animate-pulse-glow"
                  >
                    {tool.status}
                  </Badge>
                </div>
                <CardTitle className="text-lg text-glow">{tool.name}</CardTitle>
                <CardDescription className="text-muted-foreground">
                  {tool.description}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {tool.progress && (
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Scan Progress</span>
                      <span>{tool.progress}%</span>
                    </div>
                    <Progress value={tool.progress} className="glow" />
                  </div>
                )}
                <div className="flex justify-between items-center mt-4 text-sm">
                  {tool.agents && (
                    <span className="flex items-center gap-1">
                      <Server className="h-4 w-4" />
                      {tool.agents} agents
                    </span>
                  )}
                  {tool.vulnerabilities && (
                        <span className="flex items-center gap-1 text-destructive">
                          <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                          {tool.vulnerabilities} vulns
                        </span>
                  )}
                  {tool.scans && (
                    <span className="flex items-center gap-1">
                      <Activity className="h-4 w-4" />
                      {tool.scans} scans
                    </span>
                  )}
                  {tool.sources && (
                    <span className="flex items-center gap-1">
                      <Database className="h-4 w-4" />
                      {tool.sources} sources
                    </span>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Recent Alerts */}
        <Card className="gradient-card glow mb-12">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-glow">
              <AlertTriangle className="h-5 w-5" />
              Recent Security Alerts
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentAlerts.map((alert, index) => (
                <div key={index} className="flex items-center justify-between p-4 rounded-lg bg-muted/20 border border-border/30">
                  <div className="flex items-center gap-3">
                    <div className={`w-2 h-2 rounded-full ${
                      alert.type === 'critical' ? 'bg-destructive animate-pulse-glow' :
                      alert.type === 'warning' ? 'bg-accent animate-pulse' :
                      'bg-primary'
                    }`} />
                    <div>
                      <p className="font-medium">{alert.message}</p>
                      <p className="text-sm text-muted-foreground">Source: {alert.source}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Clock className="h-4 w-4" />
                    {alert.time}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
      
      {/* Security Chatbot */}
      <SecurityChatbot />
    </div>
  );
};

export default SecurityDashboard;