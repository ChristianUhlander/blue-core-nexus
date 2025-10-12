/**
 * System Status Page - Production FastAPI Backend Integration
 * Comprehensive monitoring dashboard for all security services
 */

import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Server, 
  Database, 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Wifi, 
  WifiOff,
  RefreshCw,
  ExternalLink,
  Info,
  TrendingUp,
  Eye,
  Bug
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { enhancedSecurityService, type SecurityServiceHealth } from '@/services/enhancedSecurityService';
import { config } from '@/config/environment';

const SystemStatus: React.FC = () => {
  const [serviceHealths, setServiceHealths] = useState<SecurityServiceHealth[]>([]);
  const [isWebSocketConnected, setIsWebSocketConnected] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<string>('');
  const [connectionAttempts, setConnectionAttempts] = useState(0);

  useEffect(() => {
    // Initialize data
    refreshData();
    setIsWebSocketConnected(enhancedSecurityService.isWebSocketConnected());

    // WebSocket event listeners
    const handleWebSocketConnected = () => {
      setIsWebSocketConnected(true);
      setConnectionAttempts(0);
      setLastUpdate(new Date().toISOString());
    };

    const handleWebSocketDisconnected = () => {
      setIsWebSocketConnected(false);
      setLastUpdate(new Date().toISOString());
    };

    // Service health event listeners
    const handleHealthUpdate = (event: CustomEvent) => {
      const updatedHealth = event.detail as SecurityServiceHealth;
      setServiceHealths(prev => 
        prev.map(service => 
          service.service === updatedHealth.service ? updatedHealth : service
        )
      );
      setLastUpdate(new Date().toISOString());
    };

    // Register event listeners
    window.addEventListener('security:websocket:connected', handleWebSocketConnected);
    window.addEventListener('security:websocket:disconnected', handleWebSocketDisconnected);
    
    ['gvm', 'spiderfoot'].forEach(service => {
      window.addEventListener(`security:health:${service}`, handleHealthUpdate as EventListener);
    });

    // Auto-refresh interval
    const refreshInterval = setInterval(refreshData, 30000);

    // Cleanup
    return () => {
      window.removeEventListener('security:websocket:connected', handleWebSocketConnected);
      window.removeEventListener('security:websocket:disconnected', handleWebSocketDisconnected);
      
      ['gvm', 'spiderfoot'].forEach(service => {
        window.removeEventListener(`security:health:${service}`, handleHealthUpdate as EventListener);
      });
      
      clearInterval(refreshInterval);
    };
  }, []);

  const refreshData = async () => {
    setIsRefreshing(true);
    try {
      const healthData = enhancedSecurityService.getHealthStatuses();
      setServiceHealths(healthData);
      
      await enhancedSecurityService.refreshHealthChecks();
      setLastUpdate(new Date().toISOString());
    } catch (error) {
      console.error('Failed to refresh system status:', error);
    } finally {
      setIsRefreshing(false);
    }
  };

  const getServiceIcon = (service: string) => {
    switch (service) {
      case 'gvm': return <Bug className="h-5 w-5" />;
      case 'spiderfoot': return <Eye className="h-5 w-5" />;
      default: return <Server className="h-5 w-5" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-primary';
      case 'degraded': return 'text-yellow-500';
      case 'unhealthy': return 'text-destructive';
      default: return 'text-muted-foreground';
    }
  };

  const getStatusBadgeVariant = (status: string): "default" | "secondary" | "destructive" | "outline" => {
    switch (status) {
      case 'healthy': return 'default';
      case 'degraded': return 'secondary';
      case 'unhealthy': return 'destructive';
      default: return 'outline';
    }
  };

  const overallHealthPercentage = serviceHealths.length > 0 
    ? (serviceHealths.filter(s => s.status === 'healthy').length / serviceHealths.length) * 100 
    : 0;

  const getOverallStatus = () => {
    if (overallHealthPercentage === 100) return 'All Systems Operational';
    if (overallHealthPercentage >= 75) return 'Minor Service Issues';
    if (overallHealthPercentage >= 50) return 'Degraded Performance';
    return 'Major Outage';
  };

  return (
    <div className="min-h-screen gradient-bg p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-primary mb-2">System Status</h1>
            <p className="text-muted-foreground">
              Real-time monitoring of FastAPI backend and security services
            </p>
          </div>
          
          <div className="flex items-center gap-3">
            <Badge 
              variant={isWebSocketConnected ? "default" : "destructive"}
              className={`flex items-center gap-2 ${isWebSocketConnected ? 'animate-pulse-glow' : ''}`}
            >
              {isWebSocketConnected ? (
                <>
                  <Wifi className="h-4 w-4" />
                  LIVE
                </>
              ) : (
                <>
                  <WifiOff className="h-4 w-4" />
                  OFFLINE
                </>
              )}
            </Badge>
            
            <Button 
              onClick={refreshData} 
              disabled={isRefreshing}
              variant="outline"
              size="sm"
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${isRefreshing ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </div>

        {/* Overall System Health */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="relative">
                  <Activity className={`h-6 w-6 ${getStatusColor(overallHealthPercentage === 100 ? 'healthy' : 'degraded')}`} />
                  <div className={`absolute -top-1 -right-1 w-3 h-3 rounded-full ${
                    overallHealthPercentage === 100 ? 'bg-primary animate-pulse' : 'bg-yellow-500'
                  }`} />
                </div>
                <div>
                  <CardTitle className="text-xl">{getOverallStatus()}</CardTitle>
                  <CardDescription>
                    {serviceHealths.filter(s => s.status === 'healthy').length} of {serviceHealths.length} services operational
                  </CardDescription>
                </div>
              </div>
              
              <div className="text-right">
                <div className="text-2xl font-bold text-primary">{Math.round(overallHealthPercentage)}%</div>
                <div className="text-sm text-muted-foreground">System Health</div>
              </div>
            </div>
          </CardHeader>
          
          <CardContent>
            <Progress value={overallHealthPercentage} className="h-3" />
            <div className="flex justify-between text-sm text-muted-foreground mt-2">
              <span>Last updated: {lastUpdate ? new Date(lastUpdate).toLocaleString() : 'Never'}</span>
              <span>Auto-refresh: 30s</span>
            </div>
          </CardContent>
        </Card>

        {/* Connection Status */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-5 w-5" />
                FastAPI Backend
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">WebSocket Connection</span>
                <Badge variant={isWebSocketConnected ? "default" : "destructive"}>
                  {isWebSocketConnected ? 'Connected' : 'Disconnected'}
                </Badge>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">API Endpoint</span>
                <code className="text-xs bg-muted px-2 py-1 rounded">{config.api.baseUrl}</code>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">WebSocket URL</span>
                <code className="text-xs bg-muted px-2 py-1 rounded">{config.websocket.url}</code>
              </div>

              {!isWebSocketConnected && (
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    Real-time updates are unavailable. Check your FastAPI backend WebSocket connection.
                  </AlertDescription>
                </Alert>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5" />
                Performance Metrics
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                {serviceHealths.map(service => (
                  <div key={service.service} className="flex items-center justify-between">
                    <span className="text-sm capitalize">{service.service} Response</span>
                    <span className="text-sm font-mono">
                      {service.responseTime > 0 ? `${service.responseTime}ms` : 'N/A'}
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Service Details */}
        <Tabs defaultValue="services" className="space-y-6">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="services">Security Services</TabsTrigger>
            <TabsTrigger value="configuration">Configuration</TabsTrigger>
            <TabsTrigger value="logs">System Logs</TabsTrigger>
          </TabsList>

          <TabsContent value="services" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {serviceHealths.map(service => (
                <Card key={service.service}>
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div className={getStatusColor(service.status)}>
                          {getServiceIcon(service.service)}
                        </div>
                        <CardTitle className="text-base capitalize">{service.service}</CardTitle>
                      </div>
                      <Badge variant={getStatusBadgeVariant(service.status)} className="text-xs">
                        {service.status}
                      </Badge>
                    </div>
                  </CardHeader>
                  
                  <CardContent className="space-y-3">
                    <div className="text-sm space-y-2">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Response Time</span>
                        <span className="font-mono">
                          {service.responseTime > 0 ? `${service.responseTime}ms` : 'N/A'}
                        </span>
                      </div>
                      
                      {service.version && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Version</span>
                          <span className="font-mono text-xs">{service.version}</span>
                        </div>
                      )}
                      
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Last Check</span>
                        <span className="text-xs">
                          {new Date(service.lastCheck).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                    
                    {service.error && (
                      <Alert>
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription className="text-xs">
                          {service.error}
                        </AlertDescription>
                      </Alert>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          <TabsContent value="configuration" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Environment Configuration</CardTitle>
                <CardDescription>
                  Current configuration for FastAPI backend integration
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Service</TableHead>
                      <TableHead>Base URL</TableHead>
                      <TableHead>Timeout</TableHead>
                      <TableHead>Retry Attempts</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {Object.entries(config.services).map(([service, serviceConfig]) => (
                      <TableRow key={service}>
                        <TableCell className="font-medium capitalize">{service}</TableCell>
                        <TableCell>
                          <code className="text-xs bg-muted px-2 py-1 rounded">
                            {serviceConfig.baseUrl}
                          </code>
                        </TableCell>
                        <TableCell>{serviceConfig.timeout}ms</TableCell>
                        <TableCell>{serviceConfig.retryAttempts}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="logs" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>System Events</CardTitle>
                <CardDescription>
                  Recent connection and service status events
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 font-mono text-sm">
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Clock className="h-4 w-4" />
                    <span>{new Date().toLocaleTimeString()}</span>
                    <span>System monitoring initialized</span>
                  </div>
                  
                  {serviceHealths.map(service => (
                    <div key={service.service} className="flex items-center gap-2">
                      <div className={`h-2 w-2 rounded-full ${
                        service.status === 'healthy' ? 'bg-primary' : 
                        service.status === 'degraded' ? 'bg-yellow-500' : 'bg-destructive'
                      }`} />
                      <span className="text-xs text-muted-foreground">
                        {new Date(service.lastCheck).toLocaleTimeString()}
                      </span>
                      <span className="capitalize">{service.service}</span>
                      <span className={getStatusColor(service.status)}>
                        {service.status}
                      </span>
                      {service.error && (
                        <span className="text-destructive text-xs">
                          - {service.error}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Development Mode Notice */}
        {config.development.mockData && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              <strong>Development Mode:</strong> Using mock data as FastAPI backend services are not available. 
              Connect your FastAPI backend to see real data.
            </AlertDescription>
          </Alert>
        )}
      </div>
    </div>
  );
};

export default SystemStatus;