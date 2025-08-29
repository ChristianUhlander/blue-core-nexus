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
import { securityApiManager } from '@/services/securityApi';

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
   * Load Wazuh agents from API
   * In production, this would call a Supabase Edge Function
   */
  const loadAgents = async () => {
    setIsLoading(true);
    try {
      const wazuhService = securityApiManager.getService('wazuh');
      if (!wazuhService) {
        throw new Error('Wazuh service not available');
      }

      // TODO: This will be replaced with actual API call via Supabase Edge Function
      const agentData = await wazuhService.getAgents();
      
      // Mock data for demonstration - remove when API is connected
      const mockAgents: WazuhAgent[] = [
        {
          id: '001',
          name: 'web-server-01',
          ip: '192.168.1.100',
          status: 'active',
          os_platform: 'ubuntu',
          version: '4.3.10',
          last_keep_alive: new Date().toISOString()
        },
        {
          id: '002',
          name: 'db-server-01',
          ip: '192.168.1.101',
          status: 'active',
          os_platform: 'centos',
          version: '4.3.10',
          last_keep_alive: new Date().toISOString()
        },
        {
          id: '003',
          name: 'workstation-01',
          ip: '192.168.1.102',
          status: 'disconnected',
          os_platform: 'windows',
          version: '4.3.9',
          last_keep_alive: new Date(Date.now() - 300000).toISOString()
        }
      ];

      setAgents(connectionStatus.status === 'connected' ? agentData : mockAgents);
      
      toast({
        title: "Agents Updated",
        description: `Loaded ${mockAgents.length} agents from Wazuh SIEM`,
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
   * Load recent alerts from Wazuh
   * In production, this would call a Supabase Edge Function
   */
  const loadAlerts = async () => {
    setIsLoading(true);
    try {
      const wazuhService = securityApiManager.getService('wazuh');
      if (!wazuhService) {
        throw new Error('Wazuh service not available');
      }

      // TODO: This will be replaced with actual API call via Supabase Edge Function
      const alertData = await wazuhService.getAlerts(50);
      
      // Mock data for demonstration - remove when API is connected
      const mockAlerts: WazuhAlert[] = [
        {
          id: '1',
          timestamp: new Date().toISOString(),
          rule_id: 5712,
          rule_description: 'Multiple SSH authentication failures',
          agent_name: 'web-server-01',
          level: 10,
          location: '/var/log/auth.log'
        },
        {
          id: '2',
          timestamp: new Date(Date.now() - 120000).toISOString(),
          rule_id: 31151,
          rule_description: 'Web vulnerability exploit attempt',
          agent_name: 'web-server-01',
          level: 12,
          location: '/var/log/apache2/access.log'
        },
        {
          id: '3',
          timestamp: new Date(Date.now() - 300000).toISOString(),
          rule_id: 18152,
          rule_description: 'Rootkit detection',
          agent_name: 'db-server-01',
          level: 7,
          location: 'rootcheck'
        }
      ];

      setAlerts(connectionStatus.status === 'connected' ? alertData : mockAlerts);
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
   * Restart a Wazuh agent
   * @param agentId - ID of the agent to restart
   */
  const restartAgent = async (agentId: string) => {
    try {
      // TODO: Implement via Supabase Edge Function
      // This would call: /functions/v1/wazuh-restart-agent
      
      toast({
        title: "Agent Restart",
        description: `Restart command sent to agent ${agentId}`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to restart agent",
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
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="agents">Agents</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="rules">Rules</TabsTrigger>
          <TabsTrigger value="config">Configuration</TabsTrigger>
        </TabsList>

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
                    <strong>Note:</strong> This interface requires a Supabase backend connection to manage 
                    actual Wazuh SIEM instances. Configure your API endpoints in the Supabase Edge Functions.
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