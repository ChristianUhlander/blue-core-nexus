/**
 * Wazuh SIEM Management Component
 * 
 * This component provides a comprehensive interface for managing Wazuh SIEM:
 * - Agent management and monitoring
 * - Real-time alert viewing
 * - Configuration management
 * - Connection status monitoring
 * 
 * @author Security Dashboard Team
 * @version 1.0.0
 */

import React, { useState, useEffect } from 'react';
import { Shield, Server, AlertTriangle, Play, Pause, Settings, RefreshCw, Activity } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import { useSecurityStatus } from '@/hooks/useSecurityStatus';
import { fastApiClient, WazuhAgent as FastApiWazuhAgent, WazuhAlert as FastApiWazuhAlert } from '@/services/fastApiClient';

interface WazuhAgent {
  id: string;
  name: string;
  ip: string;
  status: 'active' | 'disconnected' | 'never_connected';
  os_platform: string;
  version: string;
  last_keep_alive: string;
}

interface WazuhAlert {
  id: string;
  timestamp: string;
  rule_id: number;
  rule_description: string;
  agent_name: string;
  level: number;
  location: string;
}

const WazuhManagement: React.FC = () => {
  const { toast } = useToast();
  const { getConnectionIndicator, checkServiceConnection } = useSecurityStatus();
  
  const [agents, setAgents] = useState<WazuhAgent[]>([]);
  const [alerts, setAlerts] = useState<WazuhAlert[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('agents');

  // Connection status for Wazuh service
  const connectionStatus = getConnectionIndicator('wazuhsiem');

  /**
   * Load Wazuh agents from API via FastAPI client
   */
  const loadAgents = async () => {
    setIsLoading(true);
    try {
      const response = await fastApiClient.getWazuhAgents(100, 'status');
      
      if (!response.success) {
        throw new Error(response.error || 'Failed to load agents');
      }
      
      // Transform FastAPI response to component format
      const transformedAgents: WazuhAgent[] = (response.data || []).map(agent => ({
        id: agent.id,
        name: agent.name,
        ip: agent.ip,
        status: agent.status as 'active' | 'disconnected' | 'never_connected',
        os_platform: agent.os.platform,
        version: agent.version,
        last_keep_alive: agent.lastKeepAlive
      }));
      
      setAgents(transformedAgents);
      
      toast({
        title: "Agents Updated",
        description: `Loaded ${transformedAgents.length} agents from Wazuh SIEM`,
      });
    } catch (error) {
      console.error('Failed to load agents:', error);
      toast({
        title: "Error",
        description: "Failed to load Wazuh agents. Check connection.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Load recent alerts from Wazuh via FastAPI client
   */
  const loadAlerts = async () => {
    setIsLoading(true);
    try {
      const response = await fastApiClient.searchWazuhAlerts({ 
        size: 50,
        sort: '-timestamp'
      });
      
      if (!response.success) {
        throw new Error(response.error || 'Failed to load alerts');
      }
      
      // Transform FastAPI response to component format
      const transformedAlerts: WazuhAlert[] = (response.data || []).map(alert => ({
        id: alert.id,
        timestamp: alert.timestamp,
        rule_id: alert.rule.id,
        rule_description: alert.rule.description,
        agent_name: alert.agent.name,
        level: alert.rule.level,
        location: alert.location
      }));
      
      setAlerts(transformedAlerts);
    } catch (error) {
      console.error('Failed to load alerts:', error);
      toast({
        title: "Error",
        description: "Failed to load Wazuh alerts. Check connection.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Restart a Wazuh agent via FastAPI client
   * @param agentId - ID of the agent to restart
   */
  const restartAgent = async (agentId: string) => {
    try {
      const response = await fastApiClient.restartWazuhAgent(agentId, false);
      
      if (!response.success) {
        throw new Error(response.error || 'Failed to restart agent');
      }
      
      toast({
        title: "Agent Restart",
        description: response.data?.message || `Restart command sent to agent ${agentId}`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to restart agent",
        variant: "destructive",
      });
    }
  };

  /**
   * Test connection to Wazuh SIEM
   */
  const testConnection = async () => {
    setIsLoading(true);
    try {
      await checkServiceConnection('wazuhsiem');
      toast({
        title: "Connection Test",
        description: "Wazuh connection test completed",
      });
    } catch (error) {
      toast({
        title: "Connection Failed",
        description: "Unable to connect to Wazuh SIEM",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Load data on component mount
  useEffect(() => {
    loadAgents();
    loadAlerts();
  }, []);

  // Set default tab to overview
  useEffect(() => {
    setActiveTab('overview');
  }, []);

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header with Connection Status */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Shield className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-3xl font-bold text-glow">Wazuh SIEM Management</h1>
            <p className="text-muted-foreground">Security Information & Event Management</p>
          </div>
        </div>
        
        {/* Connection Status Indicator */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className={`w-3 h-3 rounded-full ${connectionStatus.color}`} />
            <span className="text-sm font-medium">
              {connectionStatus.status === 'connected' ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          <Button 
            onClick={testConnection} 
            disabled={isLoading}
            size="sm"
            variant="outline"
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Test Connection
          </Button>
        </div>
      </div>

      {/* Main Management Interface */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="agents">Agents</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="rules">Rules</TabsTrigger>
          <TabsTrigger value="config">Configuration</TabsTrigger>
        </TabsList>

        {/* Overview Tab - How Wazuh SIEM Works */}
        <TabsContent value="overview" className="space-y-4">
          <Card className="border-primary/20 bg-primary/5">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" />
                How Wazuh SIEM Works
              </CardTitle>
              <CardDescription>
                Understanding the log collection, analysis, and threat detection pipeline
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Data Flow Visualization */}
              <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
                <div className="text-center">
                  <div className="w-12 h-12 rounded-full bg-blue-100 flex items-center justify-center mx-auto mb-2">
                    <Server className="h-6 w-6 text-blue-600" />
                  </div>
                  <h4 className="font-semibold text-sm mb-1">1. Log Sources</h4>
                  <p className="text-xs text-muted-foreground">System logs, app logs, network events</p>
                </div>
                <div className="text-center">
                  <div className="w-12 h-12 rounded-full bg-green-100 flex items-center justify-center mx-auto mb-2">
                    <Activity className="h-6 w-6 text-green-600" />
                  </div>
                  <h4 className="font-semibold text-sm mb-1">2. Agents Collect</h4>
                  <p className="text-xs text-muted-foreground">Real-time log forwarding</p>
                </div>
                <div className="text-center">
                  <div className="w-12 h-12 rounded-full bg-purple-100 flex items-center justify-center mx-auto mb-2">
                    <Settings className="h-6 w-6 text-purple-600" />
                  </div>
                  <h4 className="font-semibold text-sm mb-1">3. Rules Engine</h4>
                  <p className="text-xs text-muted-foreground">Pattern matching & correlation</p>
                </div>
                <div className="text-center">
                  <div className="w-12 h-12 rounded-full bg-orange-100 flex items-center justify-center mx-auto mb-2">
                    <AlertTriangle className="h-6 w-6 text-orange-600" />
                  </div>
                  <h4 className="font-semibold text-sm mb-1">4. Alerts Generated</h4>
                  <p className="text-xs text-muted-foreground">Security events identified</p>
                </div>
                <div className="text-center">
                  <div className="w-12 h-12 rounded-full bg-red-100 flex items-center justify-center mx-auto mb-2">
                    <Shield className="h-6 w-6 text-red-600" />
                  </div>
                  <h4 className="font-semibold text-sm mb-1">5. Response</h4>
                  <p className="text-xs text-muted-foreground">Automated actions & notifications</p>
                </div>
                <div className="text-center">
                  <div className="w-12 h-12 rounded-full bg-indigo-100 flex items-center justify-center mx-auto mb-2">
                    <Play className="h-6 w-6 text-indigo-600" />
                  </div>
                  <h4 className="font-semibold text-sm mb-1">6. Integration</h4>
                  <p className="text-xs text-muted-foreground">SIEM dashboard & APIs</p>
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Data Sources */}
                <Card className="border-l-4 border-l-blue-500">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-lg">Data Sources & Endpoints</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div>
                      <h5 className="font-semibold text-sm mb-1">System Infrastructure</h5>
                      <ul className="text-xs text-muted-foreground space-y-1">
                        <li>• Linux: /var/log/syslog, /var/log/auth.log, /var/log/secure</li>
                        <li>• Windows: Security, System, Application event logs</li>
                        <li>• Network: Firewall logs, router/switch syslogs</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-semibold text-sm mb-1">Application Logs</h5>
                      <ul className="text-xs text-muted-foreground space-y-1">
                        <li>• Web servers: Apache/Nginx access & error logs</li>
                        <li>• Databases: MySQL, PostgreSQL, MongoDB logs</li>
                        <li>• Custom apps: Application-specific log files</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-semibold text-sm mb-1">Cloud & Containers</h5>
                      <ul className="text-xs text-muted-foreground space-y-1">
                        <li>• AWS CloudTrail, VPC Flow Logs</li>
                        <li>• Azure Activity Logs, NSG Flow Logs</li>
                        <li>• Kubernetes audit logs, Docker container logs</li>
                      </ul>
                    </div>
                  </CardContent>
                </Card>

                {/* Detection Capabilities */}
                <Card className="border-l-4 border-l-green-500">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-lg">Detection Capabilities</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div>
                      <h5 className="font-semibold text-sm mb-1">Attack Detection</h5>
                      <ul className="text-xs text-muted-foreground space-y-1">
                        <li>• Brute force attacks (SSH, RDP, web logins)</li>
                        <li>• SQL injection & web application attacks</li>
                        <li>• Privilege escalation attempts</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-semibold text-sm mb-1">System Monitoring</h5>
                      <ul className="text-xs text-muted-foreground space-y-1">
                        <li>• File integrity monitoring (FIM)</li>
                        <li>• Rootkit & malware detection</li>
                        <li>• System configuration changes</li>
                      </ul>
                    </div>
                    <div>
                      <h5 className="font-semibold text-sm mb-1">Compliance</h5>
                      <ul className="text-xs text-muted-foreground space-y-1">
                        <li>• PCI DSS, HIPAA, SOC 2 requirements</li>
                        <li>• Automated compliance reporting</li>
                        <li>• Audit trail maintenance</li>
                      </ul>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Integration Information */}
              <Card className="bg-muted/50">
                <CardContent className="p-4">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                    <div>
                      <h5 className="font-semibold mb-2">API Integration</h5>
                      <p className="text-muted-foreground">REST API on port 55000 for programmatic access to agents, alerts, and configuration.</p>
                    </div>
                    <div>
                      <h5 className="font-semibold mb-2">Real-time Processing</h5>
                      <p className="text-muted-foreground">Events processed in real-time with configurable alert thresholds and response actions.</p>
                    </div>
                    <div>
                      <h5 className="font-semibold mb-2">Scalable Architecture</h5>
                      <p className="text-muted-foreground">Supports thousands of agents with distributed processing and load balancing.</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </CardContent>
          </Card>

          {/* Current Status Overview */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="gradient-card">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 rounded-full bg-blue-100 flex items-center justify-center">
                    <Server className="h-6 w-6 text-blue-600" />
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Active Agents</p>
                    <p className="text-2xl font-bold">{agents.filter(a => a.status === 'active').length}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card className="gradient-card">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 rounded-full bg-orange-100 flex items-center justify-center">
                    <AlertTriangle className="h-6 w-6 text-orange-600" />
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Recent Alerts</p>
                    <p className="text-2xl font-bold">{alerts.length}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card className="gradient-card">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className={`w-12 h-12 rounded-full ${connectionStatus.status === 'connected' ? 'bg-green-100' : 'bg-red-100'} flex items-center justify-center`}>
                    <Shield className={`h-6 w-6 ${connectionStatus.status === 'connected' ? 'text-green-600' : 'text-red-600'}`} />
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Connection</p>
                    <p className="text-lg font-bold capitalize">{connectionStatus.status}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Agents Management Tab */}
        <TabsContent value="agents" className="space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-semibold">Agent Management</h2>
            <Button onClick={loadAgents} disabled={isLoading}>
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh Agents
            </Button>
          </div>

          <div className="grid gap-4">
            {agents.map((agent) => (
              <Card key={agent.id} className="gradient-card">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Server className="h-5 w-5 text-primary" />
                      <div>
                        <CardTitle className="text-lg">{agent.name}</CardTitle>
                        <CardDescription>{agent.ip} • {agent.os_platform}</CardDescription>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge 
                        variant={agent.status === 'active' ? 'default' : 'destructive'}
                      >
                        {agent.status}
                      </Badge>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => restartAgent(agent.id)}
                      >
                        <Play className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-3 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Version:</span>
                      <p className="font-medium">{agent.version}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Last Contact:</span>
                      <p className="font-medium">
                        {new Date(agent.last_keep_alive).toLocaleTimeString()}
                      </p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Status:</span>
                      <div className="flex items-center gap-1">
                        <div className={`w-2 h-2 rounded-full ${
                          agent.status === 'active' ? 'bg-green-500' : 'bg-red-500'
                        }`} />
                        <span className="capitalize">{agent.status.replace('_', ' ')}</span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Alerts Tab */}
        <TabsContent value="alerts" className="space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-semibold">Security Alerts</h2>
            <Button onClick={loadAlerts} disabled={isLoading}>
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh Alerts
            </Button>
          </div>

          <div className="space-y-3">
            {alerts.map((alert) => (
              <Card key={alert.id} className="gradient-card">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      <AlertTriangle className={`h-5 w-5 mt-0.5 ${
                        alert.level >= 10 ? 'text-red-500' : 
                        alert.level >= 7 ? 'text-yellow-500' : 'text-blue-500'
                      }`} />
                      <div className="space-y-1">
                        <h3 className="font-semibold">{alert.rule_description}</h3>
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          <span>Rule: {alert.rule_id}</span>
                          <span>Agent: {alert.agent_name}</span>
                          <span>Level: {alert.level}</span>
                        </div>
                        <p className="text-sm text-muted-foreground">{alert.location}</p>
                      </div>
                    </div>
                    <span className="text-sm text-muted-foreground">
                      {new Date(alert.timestamp).toLocaleString()}
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Rules Tab */}
        <TabsContent value="rules" className="space-y-4">
          <Card className="gradient-card">
            <CardHeader>
              <CardTitle>Rule Management</CardTitle>
              <CardDescription>
                Manage Wazuh detection rules and custom signatures
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-12">
                <Settings className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">Rule Management</h3>
                <p className="text-muted-foreground mb-4">
                  Advanced rule configuration requires API connection
                </p>
                <div className="flex items-center justify-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${connectionStatus.color}`} />
                  <span className="text-sm">{connectionStatus.message}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Configuration Tab */}
        <TabsContent value="config" className="space-y-4">
          <Card className="gradient-card">
            <CardHeader>
              <CardTitle>Wazuh Configuration</CardTitle>
              <CardDescription>
                System configuration and integration settings
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium">Manager Address</label>
                    <p className="text-sm text-muted-foreground">localhost:55000</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium">API Version</label>
                    <p className="text-sm text-muted-foreground">4.3.10</p>
                  </div>
                </div>
                
                <div className="pt-4 border-t">
                  <h4 className="font-semibold mb-2">Connection Status</h4>
                  <div className="flex items-center gap-3">
                    <div className={`w-3 h-3 rounded-full ${connectionStatus.color}`} />
                    <span>{connectionStatus.message}</span>
                  </div>
                </div>

                <div className="pt-4">
                  <p className="text-sm text-muted-foreground">
                    <strong>Note:</strong> This interface requires a backend connection to manage 
                    actual Wazuh SIEM instances. Configure your API endpoints in the backend service.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default WazuhManagement;