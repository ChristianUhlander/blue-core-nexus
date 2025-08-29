import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ArrowLeft, Shield, Target, FileText, Users, Settings, Key, Activity, AlertTriangle, CheckCircle, Clock, Play, Pause, Trash2, Eye } from "lucide-react";
import { Link } from "react-router-dom";

const GVMManagement = () => {
  const [searchTerm, setSearchTerm] = useState("");

  // Mock data for different sections
  const scanTasks = [
    { id: "task-001", name: "Network Infrastructure Scan", target: "192.168.1.0/24", status: "Running", progress: 67, lastRun: "2024-01-15 14:30", severity: "High" },
    { id: "task-002", name: "Web Application Scan", target: "webapp.company.com", status: "Completed", progress: 100, lastRun: "2024-01-15 10:15", severity: "Medium" },
    { id: "task-003", name: "Database Security Scan", target: "db-cluster-01", status: "Scheduled", progress: 0, lastRun: "2024-01-14 16:45", severity: "Critical" },
    { id: "task-004", name: "DMZ Perimeter Scan", target: "10.0.1.0/24", status: "Failed", progress: 25, lastRun: "2024-01-15 08:20", severity: "Low" },
  ];

  const assets = [
    { id: "asset-001", hostname: "web-server-01", ip: "192.168.1.10", os: "Ubuntu 20.04", vulnerabilities: 12, severity: "High", lastScan: "2024-01-15 14:30" },
    { id: "asset-002", hostname: "db-server-01", ip: "192.168.1.20", os: "CentOS 8", vulnerabilities: 5, severity: "Medium", lastScan: "2024-01-15 10:15" },
    { id: "asset-003", hostname: "firewall-01", ip: "10.0.1.1", os: "pfSense 2.6", vulnerabilities: 0, severity: "Low", lastScan: "2024-01-14 16:45" },
    { id: "asset-004", hostname: "mail-server", ip: "192.168.1.30", os: "Windows Server 2019", vulnerabilities: 18, severity: "Critical", lastScan: "2024-01-15 08:20" },
  ];

  const vulnerabilities = [
    { id: "vuln-001", name: "Apache HTTP Server Path Traversal", cvss: 9.8, severity: "Critical", affected: 3, category: "Web Application", published: "2024-01-10" },
    { id: "vuln-002", name: "OpenSSL Buffer Overflow", cvss: 7.5, severity: "High", affected: 8, category: "Cryptographic", published: "2024-01-08" },
    { id: "vuln-003", name: "MySQL Privilege Escalation", cvss: 6.2, severity: "Medium", affected: 2, category: "Database", published: "2024-01-12" },
    { id: "vuln-004", name: "SMB Protocol Information Disclosure", cvss: 4.3, severity: "Low", affected: 5, category: "Network", published: "2024-01-05" },
  ];

  const credentials = [
    { id: "cred-001", name: "Domain Admin Credentials", type: "Username/Password", targets: 15, lastUsed: "2024-01-15 14:30", status: "Active" },
    { id: "cred-002", name: "SSH Key Pair", type: "SSH Key", targets: 8, lastUsed: "2024-01-15 10:15", status: "Active" },
    { id: "cred-003", name: "SNMP Community String", type: "SNMP", targets: 12, lastUsed: "2024-01-14 16:45", status: "Inactive" },
    { id: "cred-004", name: "Database Service Account", type: "Username/Password", targets: 3, lastUsed: "2024-01-15 08:20", status: "Active" },
  ];

  const getStatusBadge = (status: string) => {
    const statusConfig = {
      "Running": { variant: "default" as const, icon: Play },
      "Completed": { variant: "secondary" as const, icon: CheckCircle },
      "Scheduled": { variant: "outline" as const, icon: Clock },
      "Failed": { variant: "destructive" as const, icon: AlertTriangle },
      "Active": { variant: "default" as const, icon: CheckCircle },
      "Inactive": { variant: "secondary" as const, icon: Pause },
    };
    
    const config = statusConfig[status as keyof typeof statusConfig] || { variant: "outline" as const, icon: Clock };
    const IconComponent = config.icon;
    
    return (
      <Badge variant={config.variant} className="flex items-center gap-1">
        <IconComponent className="w-3 h-3" />
        {status}
      </Badge>
    );
  };

  const getSeverityBadge = (severity: string) => {
    const severityConfig = {
      "Critical": "destructive" as const,
      "High": "destructive" as const,
      "Medium": "default" as const,
      "Low": "secondary" as const,
    };
    
    return (
      <Badge variant={severityConfig[severity as keyof typeof severityConfig] || "outline"}>
        {severity}
      </Badge>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-primary/5">
      <div className="container mx-auto p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-8 glow">
          <div>
            <h1 className="text-4xl font-bold text-glow mb-2">GVM Management Console</h1>
            <p className="text-muted-foreground">Greenbone Vulnerability Manager (OpenVAS) Security Platform</p>
          </div>
          <Link to="/">
            <Button variant="outline" className="flex items-center gap-2">
              <ArrowLeft className="w-4 h-4" />
              Back to Main Dashboard
            </Button>
          </Link>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card className="gradient-card glow-hover">
            <CardContent className="p-6 text-center">
              <Target className="w-8 h-8 mx-auto mb-2 text-primary" />
              <h3 className="text-2xl font-bold text-glow">124</h3>
              <p className="text-sm text-muted-foreground">Active Targets</p>
            </CardContent>
          </Card>
          <Card className="gradient-card glow-hover">
            <CardContent className="p-6 text-center">
              <Activity className="w-8 h-8 mx-auto mb-2 text-accent" />
              <h3 className="text-2xl font-bold text-glow">8</h3>
              <p className="text-sm text-muted-foreground">Running Scans</p>
            </CardContent>
          </Card>
          <Card className="gradient-card glow-hover">
            <CardContent className="p-6 text-center">
              <AlertTriangle className="w-8 h-8 mx-auto mb-2 text-destructive" />
              <h3 className="text-2xl font-bold text-glow">247</h3>
              <p className="text-sm text-muted-foreground">Vulnerabilities</p>
            </CardContent>
          </Card>
          <Card className="gradient-card glow-hover">
            <CardContent className="p-6 text-center">
              <Shield className="w-8 h-8 mx-auto mb-2 text-secondary" />
              <h3 className="text-2xl font-bold text-glow">98.5%</h3>
              <p className="text-sm text-muted-foreground">Scanner Health</p>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Tabs */}
        <Tabs defaultValue="tasks" className="space-y-6">
          <TabsList className="grid grid-cols-6 w-full bg-muted/50">
            <TabsTrigger value="tasks" className="flex items-center gap-2">
              <Activity className="w-4 h-4" />
              Scan Tasks
            </TabsTrigger>
            <TabsTrigger value="assets" className="flex items-center gap-2">
              <Target className="w-4 h-4" />
              Assets
            </TabsTrigger>
            <TabsTrigger value="vulnerabilities" className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Vulnerabilities
            </TabsTrigger>
            <TabsTrigger value="credentials" className="flex items-center gap-2">
              <Key className="w-4 h-4" />
              Credentials
            </TabsTrigger>
            <TabsTrigger value="reports" className="flex items-center gap-2">
              <FileText className="w-4 h-4" />
              Reports
            </TabsTrigger>
            <TabsTrigger value="configuration" className="flex items-center gap-2">
              <Settings className="w-4 h-4" />
              Configuration
            </TabsTrigger>
          </TabsList>

          <TabsContent value="tasks" className="space-y-6">
            <Card className="gradient-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="w-5 h-5" />
                  Scan Task Management
                </CardTitle>
                <CardDescription>
                  Monitor and manage vulnerability scanning tasks
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-4 mb-6">
                  <Input
                    placeholder="Search scan tasks..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="max-w-sm"
                  />
                  <Button>New Scan Task</Button>
                </div>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Task Name</TableHead>
                      <TableHead>Target</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Progress</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Last Run</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scanTasks.map((task) => (
                      <TableRow key={task.id}>
                        <TableCell className="font-medium">{task.name}</TableCell>
                        <TableCell>{task.target}</TableCell>
                        <TableCell>{getStatusBadge(task.status)}</TableCell>
                        <TableCell>
                          <div className="w-full bg-muted rounded-full h-2">
                            <div 
                              className="h-2 rounded-full bg-primary" 
                              style={{ width: `${task.progress}%` }}
                            />
                          </div>
                          <span className="text-sm text-muted-foreground">{task.progress}%</span>
                        </TableCell>
                        <TableCell>{getSeverityBadge(task.severity)}</TableCell>
                        <TableCell>{task.lastRun}</TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            <Button variant="ghost" size="sm">
                              <Eye className="w-4 h-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
                              <Play className="w-4 h-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
                              <Trash2 className="w-4 h-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="assets" className="space-y-6">
            <Card className="gradient-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Target className="w-5 h-5" />
                  Asset Management
                </CardTitle>
                <CardDescription>
                  View and manage discovered network assets
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-4 mb-6">
                  <Input
                    placeholder="Search assets..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="max-w-sm"
                  />
                  <Button>Add Target</Button>
                </div>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Hostname</TableHead>
                      <TableHead>IP Address</TableHead>
                      <TableHead>Operating System</TableHead>
                      <TableHead>Vulnerabilities</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Last Scan</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {assets.map((asset) => (
                      <TableRow key={asset.id}>
                        <TableCell className="font-medium">{asset.hostname}</TableCell>
                        <TableCell>{asset.ip}</TableCell>
                        <TableCell>{asset.os}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{asset.vulnerabilities}</Badge>
                        </TableCell>
                        <TableCell>{getSeverityBadge(asset.severity)}</TableCell>
                        <TableCell>{asset.lastScan}</TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            <Button variant="ghost" size="sm">
                              <Eye className="w-4 h-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
                              <Activity className="w-4 h-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="vulnerabilities" className="space-y-6">
            <Card className="gradient-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5" />
                  Vulnerability Management
                </CardTitle>
                <CardDescription>
                  Review and manage discovered vulnerabilities
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Vulnerability Name</TableHead>
                      <TableHead>CVSS Score</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Affected Assets</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Published</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {vulnerabilities.map((vuln) => (
                      <TableRow key={vuln.id}>
                        <TableCell className="font-medium">{vuln.name}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{vuln.cvss}</Badge>
                        </TableCell>
                        <TableCell>{getSeverityBadge(vuln.severity)}</TableCell>
                        <TableCell>{vuln.affected}</TableCell>
                        <TableCell>{vuln.category}</TableCell>
                        <TableCell>{vuln.published}</TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            <Button variant="ghost" size="sm">
                              <Eye className="w-4 h-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
                              <FileText className="w-4 h-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="credentials" className="space-y-6">
            <Card className="gradient-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Key className="w-5 h-5" />
                  Credential Management
                </CardTitle>
                <CardDescription>
                  Manage authentication credentials for authenticated scans
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-4 mb-6">
                  <Button>Add Credentials</Button>
                </div>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Credential Name</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Targets</TableHead>
                      <TableHead>Last Used</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {credentials.map((cred) => (
                      <TableRow key={cred.id}>
                        <TableCell className="font-medium">{cred.name}</TableCell>
                        <TableCell>{cred.type}</TableCell>
                        <TableCell>{cred.targets}</TableCell>
                        <TableCell>{cred.lastUsed}</TableCell>
                        <TableCell>{getStatusBadge(cred.status)}</TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            <Button variant="ghost" size="sm">
                              <Eye className="w-4 h-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
                              <Settings className="w-4 h-4" />
                            </Button>
                            <Button variant="ghost" size="sm">
                              <Trash2 className="w-4 h-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="reports" className="space-y-6">
            <Card className="gradient-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileText className="w-5 h-5" />
                  Report Management
                </CardTitle>
                <CardDescription>
                  Generate and manage vulnerability scan reports
                </CardDescription>
              </CardHeader>
              <CardContent className="text-center py-12">
                <FileText className="w-12 h-12 mx-auto mb-4 text-muted-foreground" />
                <h3 className="text-lg font-semibold mb-2">Report Generation</h3>
                <p className="text-muted-foreground mb-4">
                  Configure and generate detailed vulnerability reports in various formats
                </p>
                <Button>Generate Report</Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="configuration" className="space-y-6">
            <Card className="gradient-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="w-5 h-5" />
                  Scanner Configuration
                </CardTitle>
                <CardDescription>
                  Configure scan policies, schedules, and system settings
                </CardDescription>
              </CardHeader>
              <CardContent className="text-center py-12">
                <Settings className="w-12 h-12 mx-auto mb-4 text-muted-foreground" />
                <h3 className="text-lg font-semibold mb-2">Configuration Settings</h3>
                <p className="text-muted-foreground mb-4">
                  Manage scan configurations, policies, and system preferences
                </p>
                <Button>Configure Scanner</Button>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default GVMManagement;