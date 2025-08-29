import { Shield, Eye, Zap, Search, Activity, AlertTriangle, CheckCircle, Clock, Server, Database, Wifi, WifiOff, Users, Settings } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import SecurityChatbot from "./SecurityChatbot";
import { useSecurityStatus } from "@/hooks/useSecurityStatus";
import heroImage from "@/assets/security-hero.jpg";
import { useState } from "react";

const SecurityDashboard = () => {
  const { getConnectionIndicator } = useSecurityStatus();
  const [isAgentStatusOpen, setIsAgentStatusOpen] = useState(false);

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
                          <Button variant="outline" size="sm" className="glow-hover">
                            <Users className="h-4 w-4 mr-2" />
                            View Agent Status
                          </Button>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-[900px] max-h-[80vh] gradient-card">
                          <DialogHeader>
                            <DialogTitle className="flex items-center gap-2">
                              <Server className="h-5 w-5 text-primary" />
                              Security Agent Status Dashboard
                            </DialogTitle>
                            <DialogDescription>
                              Monitor all security agents and API connections across your infrastructure
                            </DialogDescription>
                          </DialogHeader>

                          <div className="space-y-6">
                            {/* API Connection Status */}
                            <div className="space-y-3">
                              <h3 className="text-lg font-semibold flex items-center gap-2">
                                <Wifi className="h-5 w-5 text-primary" />
                                API Connection Status
                              </h3>
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                {apiConnections.map((connection) => (
                                  <Card key={connection.service} className="gradient-card border">
                                    <CardContent className="p-4">
                                      <div className="flex items-center justify-between mb-2">
                                        <div className="flex items-center gap-2">
                                          <div className={`w-3 h-3 rounded-full ${
                                            connection.status === 'connected' 
                                              ? 'bg-green-500 animate-pulse-glow shadow-glow' 
                                              : 'bg-red-500 animate-pulse shadow-red-500/50'
                                          }`} />
                                          <span className="font-medium text-sm">{connection.service}</span>
                                        </div>
                                        <Badge 
                                          variant={connection.status === 'connected' ? 'default' : 'destructive'}
                                          className="text-xs"
                                        >
                                          {connection.status === 'connected' ? 'ONLINE' : 'OFFLINE'}
                                        </Badge>
                                      </div>
                                      <p className="text-xs text-muted-foreground mb-1">{connection.endpoint}</p>
                                      <p className="text-xs text-muted-foreground">{connection.description}</p>
                                    </CardContent>
                                  </Card>
                                ))}
                              </div>
                            </div>

                            {/* Agent Status Table */}
                            <div className="space-y-3">
                              <div className="flex items-center justify-between">
                                <h3 className="text-lg font-semibold flex items-center gap-2">
                                  <Server className="h-5 w-5 text-primary" />
                                  Wazuh Agents ({agentData.length} Total)
                                </h3>
                                <div className="flex gap-2 text-sm">
                                  <Badge variant="default" className="text-xs">
                                    {agentData.filter(a => a.status === 'active').length} Active
                                  </Badge>
                                  <Badge variant="destructive" className="text-xs">
                                    {agentData.filter(a => a.status === 'disconnected').length} Disconnected
                                  </Badge>
                                  <Badge variant="secondary" className="text-xs">
                                    {agentData.filter(a => a.status === 'never_connected').length} Never Connected
                                  </Badge>
                                </div>
                              </div>

                              <ScrollArea className="h-[350px] rounded-md border">
                                <Table>
                                  <TableHeader>
                                    <TableRow>
                                      <TableHead>Agent ID</TableHead>
                                      <TableHead>Name</TableHead>
                                      <TableHead>IP Address</TableHead>
                                      <TableHead>OS</TableHead>
                                      <TableHead>Status</TableHead>
                                      <TableHead>Last Seen</TableHead>
                                      <TableHead>Version</TableHead>
                                      <TableHead>Group</TableHead>
                                    </TableRow>
                                  </TableHeader>
                                  <TableBody>
                                    {agentData.map((agent) => (
                                      <TableRow key={agent.id}>
                                        <TableCell className="font-mono text-sm">{agent.id}</TableCell>
                                        <TableCell className="font-medium">{agent.name}</TableCell>
                                        <TableCell className="font-mono text-sm">{agent.ip}</TableCell>
                                        <TableCell className="text-sm">{agent.os}</TableCell>
                                        <TableCell>
                                          <div className="flex items-center gap-2">
                                            <div className={`w-2 h-2 rounded-full ${
                                              agent.status === 'active' 
                                                ? 'bg-green-500 animate-pulse-glow shadow-glow' 
                                                : agent.status === 'disconnected'
                                                ? 'bg-red-500 animate-pulse shadow-red-500/50'
                                                : 'bg-yellow-500 animate-pulse shadow-yellow-500/50'
                                            }`} />
                                            <Badge 
                                              variant={
                                                agent.status === 'active' ? 'default' : 
                                                agent.status === 'disconnected' ? 'destructive' : 'secondary'
                                              }
                                              className="text-xs"
                                            >
                                              {agent.status.replace('_', ' ').toUpperCase()}
                                            </Badge>
                                          </div>
                                        </TableCell>
                                        <TableCell className="text-sm">{agent.lastSeen}</TableCell>
                                        <TableCell className="font-mono text-sm">{agent.version}</TableCell>
                                        <TableCell className="text-sm">
                                          <Badge variant="outline" className="text-xs">
                                            {agent.group}
                                          </Badge>
                                        </TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              </ScrollArea>
                            </div>

                            {/* Quick Stats */}
                            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 pt-4 border-t">
                              <div className="text-center">
                                <div className="text-2xl font-bold text-green-500">{agentData.filter(a => a.status === 'active').length}</div>
                                <div className="text-xs text-muted-foreground">Active Agents</div>
                              </div>
                              <div className="text-center">
                                <div className="text-2xl font-bold text-red-500">{agentData.filter(a => a.status === 'disconnected').length}</div>
                                <div className="text-xs text-muted-foreground">Disconnected</div>
                              </div>
                              <div className="text-center">
                                <div className="text-2xl font-bold text-yellow-500">{agentData.filter(a => a.status === 'never_connected').length}</div>
                                <div className="text-xs text-muted-foreground">Never Connected</div>
                              </div>
                              <div className="text-center">
                                <div className="text-2xl font-bold text-primary">{apiConnections.filter(c => c.status === 'connected').length}/{apiConnections.length}</div>
                                <div className="text-xs text-muted-foreground">APIs Online</div>
                              </div>
                            </div>
                          </div>

                          <div className="flex justify-end gap-2 pt-4">
                            <Button variant="outline" onClick={() => setIsAgentStatusOpen(false)}>
                              Close
                            </Button>
                            <Button className="glow-hover">
                              <Settings className="h-4 w-4 mr-2" />
                              Manage Agents
                            </Button>
                          </div>
                        </DialogContent>
                      </Dialog>
                      <Button variant="outline" size="sm">
                        Agent Configuration
                      </Button>
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
                      <Button variant="outline" size="sm">
                        CVE Assessment
                      </Button>
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