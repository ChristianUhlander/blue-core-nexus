/**
 * MCP Bridge Status Indicator Component
 * Shows real-time status of MCP Bridge connection
 */

import React, { useState, useEffect } from 'react';
import { Wifi, WifiOff, AlertTriangle, CheckCircle, Clock, RefreshCw } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

interface MCPBridgeStatusIndicatorProps {
  className?: string;
  compact?: boolean;
}

export const MCPBridgeStatusIndicator: React.FC<MCPBridgeStatusIndicatorProps> = ({ 
  className = "", 
  compact = false 
}) => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<string>('');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [responseTime, setResponseTime] = useState<number>(0);

  const checkConnection = async () => {
    setIsRefreshing(true);
    const startTime = Date.now();
    
    try {
      // TODO: Replace with actual MCP Bridge API endpoint check
      // For now, simulating connection check
      await new Promise(resolve => setTimeout(resolve, 500));
      
      const endTime = Date.now();
      setResponseTime(endTime - startTime);
      setIsConnected(false); // Set to true when actual endpoint is available
      setError('MCP Bridge endpoint not configured');
      setLastUpdate(new Date().toISOString());
    } catch (err) {
      setIsConnected(false);
      setError(err instanceof Error ? err.message : 'Connection failed');
      setLastUpdate(new Date().toISOString());
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    checkConnection();
    
    // Check connection every 30 seconds
    const interval = setInterval(checkConnection, 30000);
    
    return () => clearInterval(interval);
  }, []);

  const getStatusIcon = () => {
    if (isConnected) {
      return <CheckCircle className="h-4 w-4 text-primary" />;
    }
    return <AlertTriangle className="h-4 w-4 text-destructive" />;
  };

  if (compact) {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <div className={`flex items-center gap-2 px-3 py-2 rounded-md border ${className}`}>
              {isConnected ? (
                <Wifi className="h-4 w-4 text-primary" />
              ) : (
                <WifiOff className="h-4 w-4 text-muted-foreground" />
              )}
              
              {getStatusIcon()}
              
              <Badge variant={isConnected ? 'default' : 'destructive'}>
                {isConnected ? 'Connected' : 'Offline'}
              </Badge>
            </div>
          </TooltipTrigger>
          <TooltipContent>
            <div className="space-y-2">
              <div className="font-medium">MCP Bridge Status</div>
              <div className="text-sm">
                Connection: {isConnected ? 'Active' : 'Disconnected'}
              </div>
              {error && (
                <div className="text-xs text-destructive">{error}</div>
              )}
              <div className="text-xs text-muted-foreground">
                Last check: {new Date(lastUpdate).toLocaleTimeString()}
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
              {isConnected ? (
                <Wifi className="h-5 w-5 text-primary" />
              ) : (
                <WifiOff className="h-5 w-5 text-muted-foreground" />
              )}
              <div className={`absolute -top-1 -right-1 w-3 h-3 rounded-full ${
                isConnected ? 'bg-primary animate-pulse' : 'bg-muted-foreground'
              }`} />
            </div>
            MCP Bridge Status
          </CardTitle>
          
          <div className="flex items-center gap-2">
            <Badge 
              variant={isConnected ? 'default' : 'secondary'}
              className={isConnected ? 'animate-pulse-glow' : ''}
            >
              {isConnected ? 'CONNECTED' : 'OFFLINE'}
            </Badge>
            
            <Button
              variant="ghost"
              size="sm"
              onClick={checkConnection}
              disabled={isRefreshing}
              className="h-8 w-8 p-0"
            >
              <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            </Button>
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {/* Connection Status */}
        <div className="space-y-2">
          <div className="text-sm font-medium text-muted-foreground">Connection Details</div>
          <div className="flex items-center justify-between p-3 rounded-md border">
            <div className="flex items-center gap-3">
              <div className={`w-3 h-3 rounded-full ${
                isConnected ? 'bg-primary animate-pulse' : 'bg-destructive'
              }`} />
              <div>
                <div className="font-medium">Model Context Protocol Bridge</div>
                <div className="text-xs text-muted-foreground">
                  AI Agent Integration Layer
                </div>
              </div>
            </div>
            {getStatusIcon()}
          </div>
        </div>

        {/* Performance Metrics */}
        {isConnected && (
          <div className="grid grid-cols-2 gap-2">
            <div className="p-2 rounded-md border">
              <div className="text-xs text-muted-foreground">Response Time</div>
              <div className="text-lg font-medium">{responseTime}ms</div>
            </div>
            <div className="p-2 rounded-md border">
              <div className="text-xs text-muted-foreground">Status</div>
              <div className="text-lg font-medium text-primary">Active</div>
            </div>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="p-3 rounded-md border border-destructive/50 bg-destructive/10">
            <div className="text-sm font-medium text-destructive">Connection Error</div>
            <div className="text-xs text-muted-foreground mt-1">{error}</div>
          </div>
        )}

        {/* Connection Info */}
        <div className="pt-2 border-t">
          <div className="text-xs text-muted-foreground">
            Last check: {lastUpdate ? new Date(lastUpdate).toLocaleString() : 'Never'}
          </div>
          {!isConnected && (
            <div className="text-xs text-destructive mt-1">
              MCP Bridge connection unavailable - check configuration
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
