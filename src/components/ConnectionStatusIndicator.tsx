/**
 * Connection Status Indicator Component
 * Shows real-time status of FastAPI backend and security services
 */

import React, { useState, useEffect } from 'react';
import { Wifi, WifiOff, AlertTriangle, CheckCircle, Clock, RefreshCw } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { enhancedSecurityService, type SecurityServiceHealth } from '@/services/enhancedSecurityService';

interface ConnectionStatusIndicatorProps {
  className?: string;
  compact?: boolean;
}

export const ConnectionStatusIndicator: React.FC<ConnectionStatusIndicatorProps> = ({ 
  className = "", 
  compact = false 
}) => {
  const [isWebSocketConnected, setIsWebSocketConnected] = useState(false);
  const [serviceHealths, setServiceHealths] = useState<SecurityServiceHealth[]>([]);
  const [lastUpdate, setLastUpdate] = useState<string>('');
  const [isRefreshing, setIsRefreshing] = useState(false);

  useEffect(() => {
    // Initialize service health data
    const healthData = enhancedSecurityService.getHealthStatuses();
    setServiceHealths(healthData);
    setIsWebSocketConnected(enhancedSecurityService.isWebSocketConnected());
    setLastUpdate(new Date().toISOString());

    // WebSocket connection events
    const handleWebSocketConnected = () => {
      setIsWebSocketConnected(true);
      setLastUpdate(new Date().toISOString());
    };

    const handleWebSocketDisconnected = () => {
      setIsWebSocketConnected(false);
      setLastUpdate(new Date().toISOString());
    };

    // Service health update events
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
    
    ['wazuh', 'gvm'].forEach(service => {
      window.addEventListener(`security:health:${service}`, handleHealthUpdate as EventListener);
    });

    // Cleanup
    return () => {
      window.removeEventListener('security:websocket:connected', handleWebSocketConnected);
      window.removeEventListener('security:websocket:disconnected', handleWebSocketDisconnected);
      
      ['wazuh', 'gvm'].forEach(service => {
        window.removeEventListener(`security:health:${service}`, handleHealthUpdate as EventListener);
      });
    };
  }, []);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await enhancedSecurityService.refreshHealthChecks();
    } catch (error) {
      console.error('Failed to refresh health checks:', error);
    } finally {
      setIsRefreshing(false);
    }
  };

  const getOverallStatus = () => {
    const healthyServices = serviceHealths.filter(s => s.status === 'healthy').length;
    const totalServices = serviceHealths.length;
    
    if (healthyServices === 0) return 'critical';
    if (healthyServices < totalServices / 2) return 'degraded';
    if (healthyServices < totalServices) return 'partial';
    return 'healthy';
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle className="h-4 w-4 text-primary" />;
      case 'degraded':
      case 'partial':
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case 'critical':
      case 'unhealthy':
        return <AlertTriangle className="h-4 w-4 text-destructive" />;
      default:
        return <Clock className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'bg-primary';
      case 'degraded':
        return 'bg-yellow-500';
      case 'unhealthy':
        return 'bg-destructive';
      default:
        return 'bg-muted-foreground';
    }
  };

  const overallStatus = getOverallStatus();
  const healthyCount = serviceHealths.filter(s => s.status === 'healthy').length;
  const healthPercentage = serviceHealths.length > 0 ? (healthyCount / serviceHealths.length) * 100 : 0;

  if (compact) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <div className={`flex items-center gap-2 px-3 py-2 rounded-md border ${className}`}>
              {isWebSocketConnected ? (
                <Wifi className="h-4 w-4 text-primary" />
              ) : (
                <WifiOff className="h-4 w-4 text-muted-foreground" />
              )}
              
              {getStatusIcon(overallStatus)}
              
              <Badge variant={overallStatus === 'healthy' ? 'default' : 'destructive'}>
                {healthyCount}/{serviceHealths.length}
              </Badge>
            </div>
          </TooltipTrigger>
          <TooltipContent>
            <div className="space-y-2">
              <div className="font-medium">System Status</div>
              <div className="text-sm">
                WebSocket: {isWebSocketConnected ? 'Connected' : 'Disconnected'}
              </div>
              <div className="text-sm">
                Services: {healthyCount} of {serviceHealths.length} healthy
              </div>
              <div className="text-xs text-muted-foreground">
                Last update: {new Date(lastUpdate).toLocaleTimeString()}
              </div>
            </div>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  return (
    <Card className={className}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg flex items-center gap-2">
            <div className="relative">
              {isWebSocketConnected ? (
                <Wifi className="h-5 w-5 text-primary" />
              ) : (
                <WifiOff className="h-5 w-5 text-muted-foreground" />
              )}
              <div className={`absolute -top-1 -right-1 w-3 h-3 rounded-full ${
                isWebSocketConnected ? 'bg-primary animate-pulse' : 'bg-muted-foreground'
              }`} />
            </div>
            FastAPI Backend Status
          </CardTitle>
          
          <div className="flex items-center gap-2">
            <Badge 
              variant={isWebSocketConnected ? 'default' : 'secondary'}
              className={isWebSocketConnected ? 'animate-pulse-glow' : ''}
            >
              {isWebSocketConnected ? 'LIVE' : 'OFFLINE'}
            </Badge>
            
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRefresh}
              disabled={isRefreshing}
              className="h-8 w-8 p-0"
            >
              <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            </Button>
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {/* Overall Health Progress */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">System Health</span>
            <span className="font-medium">{Math.round(healthPercentage)}%</span>
          </div>
          <Progress 
            value={healthPercentage} 
            className="h-2"
          />
        </div>

        {/* Individual Service Status */}
        <div className="space-y-2">
          <div className="text-sm font-medium text-muted-foreground">Security Services</div>
          <div className="grid grid-cols-2 gap-2">
            {serviceHealths.map((service) => (
              <TooltipProvider key={service.service}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="flex items-center justify-between p-2 rounded-md border hover:bg-muted/50 cursor-default">
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${getStatusColor(service.status)}`} />
                        <span className="text-sm capitalize">{service.service}</span>
                      </div>
                      {getStatusIcon(service.status)}
                    </div>
                  </TooltipTrigger>
                  <TooltipContent>
                    <div className="space-y-1 text-sm">
                      <div className="font-medium">{service.service.toUpperCase()}</div>
                      <div>Status: <span className="capitalize">{service.status}</span></div>
                      <div>Response: {service.responseTime}ms</div>
                      {service.version && (
                        <div>Version: {service.version}</div>
                      )}
                      {service.error && (
                        <div className="text-destructive">Error: {service.error}</div>
                      )}
                      <div className="text-xs text-muted-foreground">
                        Last check: {new Date(service.lastCheck).toLocaleTimeString()}
                      </div>
                    </div>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            ))}
          </div>
        </div>

        {/* Connection Info */}
        <div className="pt-2 border-t">
          <div className="text-xs text-muted-foreground">
            Last update: {new Date(lastUpdate).toLocaleString()}
          </div>
          {!isWebSocketConnected && (
            <div className="text-xs text-destructive mt-1">
              Real-time updates unavailable - check FastAPI WebSocket connection
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};