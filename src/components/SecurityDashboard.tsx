import { Shield, Eye, Zap, Search, Activity, AlertTriangle, CheckCircle, Clock, Server, Database } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import SecurityChatbot from "./SecurityChatbot";
import heroImage from "@/assets/security-hero.jpg";

const SecurityDashboard = () => {
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
              Security Operations Center
            </h1>
            <p className="text-xl text-muted-foreground mb-8">
              Unified cybersecurity monitoring with Wazuh, OpenVAS, OWASP ZAP, and Spiderfoot intelligence
            </p>
            <div className="flex gap-4">
              <Button variant="default" size="lg" className="glow-hover">
                Deploy New Agent
              </Button>
              <Button variant="outline" size="lg" className="glow-hover">
                Schedule Scan
              </Button>
            </div>
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
                      <AlertTriangle className="h-4 w-4" />
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

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="gradient-card glow-hover">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" />
                Agent Management
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button 
                className="w-full glow-hover" 
                variant="default"
                onClick={() => window.location.href = '/wazuh'}
              >
                Manage Wazuh SIEM
              </Button>
              <Button className="w-full" variant="outline">
                View Agent Status
              </Button>
              <Button className="w-full" variant="outline">
                Agent Configuration
              </Button>
            </CardContent>
          </Card>

          <Card className="gradient-card glow-hover">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Eye className="h-5 w-5 text-secondary" />
                Vulnerability Scans
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button 
                className="w-full glow-hover" 
                variant="default"
                onClick={() => window.location.href = '/gvm'}
              >
                Manage GVM/OpenVAS
              </Button>
              <Button className="w-full" variant="outline">
                CVE Assessment
              </Button>
              <Button className="w-full" variant="outline">
                Scan Results
              </Button>
            </CardContent>
          </Card>

          <Card className="gradient-card glow-hover">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5 text-accent" />
                Security Testing
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Button className="w-full glow-hover" variant="default">
                OWASP Top 10 Scan
              </Button>
              <Button className="w-full" variant="outline">
                Custom ZAP Scan
              </Button>
              <Button className="w-full" variant="outline">
                OSINT Monitoring
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
      
      {/* Security Chatbot */}
      <SecurityChatbot />
    </div>
  );
};

export default SecurityDashboard;