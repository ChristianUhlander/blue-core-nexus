/**
 * Wazuh SIEM Management Page
 * Comprehensive Wazuh agent and alert management interface
 */

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  Server,
  AlertTriangle,
  Activity,
  RefreshCw,
  ArrowLeft,
  Search,
  Filter,
  Download,
  Settings,
  Play,
  Pause,
  Trash2,
  Eye,
  ChevronDown,
  CheckCircle,
  XCircle,
  Clock,
  TrendingUp,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { wazuhApi } from '@/services/wazuhApi';
import type { WazuhAgent, WazuhAlert } from '@/types/security';

const WazuhManagement = () => {
  const navigate = useNavigate();
  const { toast } = useToast();

  // State management
  const [agents, setAgents] = useState<WazuhAgent[]>([]);
  const [alerts, setAlerts] = useState<WazuhAlert[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [selectedAgent, setSelectedAgent] = useState<WazuhAgent | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<WazuhAlert | null>(null);
  const [isAgentDialogOpen, setIsAgentDialogOpen] = useState(false);
  const [isAlertDialogOpen, setIsAlertDialogOpen] = useState(false);

  // Statistics
  const [stats, setStats] = useState({
    agents: { total: 0, active: 0, disconnected: 0, neverConnected: 0, pending: 0 },
    alerts: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
  });

  // Load data on mount
  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [agentsData, alertsData, agentStats, alertStats] = await Promise.all([
        wazuhApi.getAgents({ limit: 100 }),
        wazuhApi.getAlerts({ limit: 100, ruleLevel: 3 }),
        wazuhApi.getAgentStats(),
        wazuhApi.getAlertStats('24h'),
      ]);

      setAgents(agentsData);
      setAlerts(alertsData);
      setStats({
        agents: agentStats,
        alerts: alertStats,
      });
    } catch (error) {
      toast({
        title: 'Failed to load Wazuh data',
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleRefresh = () => {
    loadData();
    toast({
      title: 'Refreshing data',
      description: 'Loading latest Wazuh data...',
    });
  };

  const handleRestartAgent = async (agentId: string) => {
    try {
      await wazuhApi.restartAgent(agentId);
      toast({
        title: 'Agent restart initiated',
        description: `Agent ${agentId} is restarting...`,
      });
      loadData();
    } catch (error) {
      toast({
        title: 'Failed to restart agent',
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  const handleViewAgent = (agent: WazuhAgent) => {
    setSelectedAgent(agent);
    setIsAgentDialogOpen(true);
  };

  const handleViewAlert = (alert: WazuhAlert) => {
    setSelectedAlert(alert);
    setIsAlertDialogOpen(true);
  };

  // Filter agents
  const filteredAgents = agents.filter(agent => {
    const matchesSearch = agent.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         agent.ip.includes(searchQuery);
    const matchesStatus = statusFilter === 'all' || agent.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  // Filter alerts
  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch = alert.ruleDescription.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         alert.agentName.toLowerCase().includes(searchQuery.toLowerCase());
    let matchesSeverity = true;
    if (severityFilter !== 'all') {
      if (severityFilter === 'critical') matchesSeverity = alert.ruleLevel >= 12;
      else if (severityFilter === 'high') matchesSeverity = alert.ruleLevel >= 8 && alert.ruleLevel < 12;
      else if (severityFilter === 'medium') matchesSeverity = alert.ruleLevel >= 5 && alert.ruleLevel < 8;
      else if (severityFilter === 'low') matchesSeverity = alert.ruleLevel < 5;
    }
    return matchesSearch && matchesSeverity;
  });

  const getStatusBadge = (status: string) => {
    const variants: Record<string, { variant: 'default' | 'secondary' | 'destructive' | 'outline'; icon: any }> = {
      active: { variant: 'default', icon: CheckCircle },
      disconnected: { variant: 'destructive', icon: XCircle },
      never_connected: { variant: 'secondary', icon: Clock },
      pending: { variant: 'outline', icon: Clock },
    };
    const config = variants[status] || variants.pending;
    const Icon = config.icon;
    return (
      <Badge variant={config.variant} className="gap-1">
        <Icon className="h-3 w-3" />
        {status}
      </Badge>
    );
  };

  const getSeverityBadge = (level: number) => {
    if (level >= 12) return <Badge variant="destructive">Critical</Badge>;
    if (level >= 8) return <Badge className="bg-orange-500">High</Badge>;
    if (level >= 5) return <Badge className="bg-yellow-500">Medium</Badge>;
    return <Badge variant="secondary">Low</Badge>;
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="border-b bg-card">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Button variant="ghost" size="icon" onClick={() => navigate('/')}>
                <ArrowLeft className="h-5 w-5" />
              </Button>
              <div>
                <h1 className="text-2xl font-bold flex items-center gap-2">
                  <Shield className="h-6 w-6 text-primary" />
                  Wazuh SIEM Management
                </h1>
                <p className="text-sm text-muted-foreground">
                  Security Information and Event Management
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={handleRefresh} disabled={isLoading}>
                <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div className="container mx-auto px-4 py-6 space-y-6">
        {/* Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Total Agents</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.agents.total}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-500" />
                Active
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{stats.agents.active}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                <XCircle className="h-4 w-4 text-red-500" />
                Disconnected
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{stats.agents.disconnected}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Total Alerts (24h)</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.alerts.total}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-red-500" />
                Critical
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{stats.alerts.critical}</div>
            </CardContent>
          </Card>
        </div>

        {/* Main Content */}
        <Tabs defaultValue="agents" className="space-y-4">
          <TabsList>
            <TabsTrigger value="agents" className="flex items-center gap-2">
              <Server className="h-4 w-4" />
              Agents
            </TabsTrigger>
            <TabsTrigger value="alerts" className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Alerts
            </TabsTrigger>
          </TabsList>

          {/* Agents Tab */}
          <TabsContent value="agents" className="space-y-4">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>Wazuh Agents</CardTitle>
                    <CardDescription>Monitor and manage security agents</CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="relative">
                      <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                      <Input
                        placeholder="Search agents..."
                        className="pl-8 w-64"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                      />
                    </div>
                    <Select value={statusFilter} onValueChange={setStatusFilter}>
                      <SelectTrigger className="w-40">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Status</SelectItem>
                        <SelectItem value="active">Active</SelectItem>
                        <SelectItem value="disconnected">Disconnected</SelectItem>
                        <SelectItem value="never_connected">Never Connected</SelectItem>
                        <SelectItem value="pending">Pending</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[500px]">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Agent ID</TableHead>
                        <TableHead>Name</TableHead>
                        <TableHead>IP Address</TableHead>
                        <TableHead>OS</TableHead>
                        <TableHead>Version</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Last Seen</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredAgents.map((agent) => (
                        <TableRow key={agent.id}>
                          <TableCell className="font-mono">{agent.id}</TableCell>
                          <TableCell className="font-medium">{agent.name}</TableCell>
                          <TableCell>{agent.ip}</TableCell>
                          <TableCell>
                            {agent.os.platform} {agent.os.version}
                          </TableCell>
                          <TableCell>{agent.version}</TableCell>
                          <TableCell>{getStatusBadge(agent.status)}</TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {agent.lastKeepAlive ? new Date(agent.lastKeepAlive).toLocaleString() : 'Never'}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleViewAgent(agent)}
                              >
                                <Eye className="h-4 w-4" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleRestartAgent(agent.id)}
                                disabled={agent.status !== 'active'}
                              >
                                <RefreshCw className="h-4 w-4" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Alerts Tab */}
          <TabsContent value="alerts" className="space-y-4">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>Security Alerts</CardTitle>
                    <CardDescription>Recent security events and alerts</CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="relative">
                      <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                      <Input
                        placeholder="Search alerts..."
                        className="pl-8 w-64"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                      />
                    </div>
                    <Select value={severityFilter} onValueChange={setSeverityFilter}>
                      <SelectTrigger className="w-40">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Severity</SelectItem>
                        <SelectItem value="critical">Critical</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="low">Low</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[500px]">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Timestamp</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead>Rule</TableHead>
                        <TableHead>Description</TableHead>
                        <TableHead>Agent</TableHead>
                        <TableHead>Source IP</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredAlerts.map((alert) => (
                        <TableRow key={alert.id}>
                          <TableCell className="text-sm">
                            {new Date(alert.timestamp).toLocaleString()}
                          </TableCell>
                          <TableCell>{getSeverityBadge(alert.ruleLevel)}</TableCell>
                          <TableCell className="font-mono text-sm">{alert.ruleId}</TableCell>
                          <TableCell className="max-w-md truncate">{alert.ruleDescription}</TableCell>
                          <TableCell>{alert.agentName}</TableCell>
                          <TableCell className="font-mono text-sm">{alert.srcIp || '-'}</TableCell>
                          <TableCell>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleViewAlert(alert)}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>

      {/* Agent Details Dialog */}
      <Dialog open={isAgentDialogOpen} onOpenChange={setIsAgentDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Agent Details</DialogTitle>
            <DialogDescription>Complete information about the selected agent</DialogDescription>
          </DialogHeader>
          {selectedAgent && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">Agent ID</p>
                  <p className="font-mono">{selectedAgent.id}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Status</p>
                  {getStatusBadge(selectedAgent.status)}
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Name</p>
                  <p className="font-medium">{selectedAgent.name}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">IP Address</p>
                  <p className="font-mono">{selectedAgent.ip}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Operating System</p>
                  <p>{selectedAgent.os.name || `${selectedAgent.os.platform} ${selectedAgent.os.version}`}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Agent Version</p>
                  <p>{selectedAgent.version}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Date Added</p>
                  <p>{new Date(selectedAgent.dateAdd).toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Last Keep Alive</p>
                  <p>{selectedAgent.lastKeepAlive ? new Date(selectedAgent.lastKeepAlive).toLocaleString() : 'Never'}</p>
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Alert Details Dialog */}
      <Dialog open={isAlertDialogOpen} onOpenChange={setIsAlertDialogOpen}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>Alert Details</DialogTitle>
            <DialogDescription>Complete information about the security alert</DialogDescription>
          </DialogHeader>
          {selectedAlert && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">Timestamp</p>
                  <p>{new Date(selectedAlert.timestamp).toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Severity</p>
                  {getSeverityBadge(selectedAlert.ruleLevel)}
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Rule ID</p>
                  <p className="font-mono">{selectedAlert.ruleId}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Rule Level</p>
                  <p>{selectedAlert.ruleLevel}</p>
                </div>
                <div className="col-span-2">
                  <p className="text-sm text-muted-foreground">Description</p>
                  <p>{selectedAlert.ruleDescription}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Agent</p>
                  <p>{selectedAlert.agentName} ({selectedAlert.agentId})</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Location</p>
                  <p>{selectedAlert.location}</p>
                </div>
                {selectedAlert.srcIp && (
                  <div>
                    <p className="text-sm text-muted-foreground">Source IP</p>
                    <p className="font-mono">{selectedAlert.srcIp}</p>
                  </div>
                )}
                {selectedAlert.dstIp && (
                  <div>
                    <p className="text-sm text-muted-foreground">Destination IP</p>
                    <p className="font-mono">{selectedAlert.dstIp}</p>
                  </div>
                )}
                {selectedAlert.mitre && (
                  <div className="col-span-2">
                    <p className="text-sm text-muted-foreground">MITRE ATT&CK</p>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {selectedAlert.mitre.technique.map((tech, idx) => (
                        <Badge key={idx} variant="outline">{tech}</Badge>
                      ))}
                    </div>
                  </div>
                )}
                <div className="col-span-2">
                  <p className="text-sm text-muted-foreground">Full Log</p>
                  <ScrollArea className="h-32 mt-2 rounded-md border p-3">
                    <pre className="text-xs font-mono">{selectedAlert.fullLog}</pre>
                  </ScrollArea>
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default WazuhManagement;
