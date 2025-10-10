/**
 * Real-time Security Data Hook
 * Manages WebSocket connections and real-time updates from security services
 * 
 * BACKEND INTEGRATION:
 * - WebSocket server at /ws endpoint
 * - Real-time event streaming from security tools
 * - Automatic reconnection and error handling
 * - State synchronization across multiple browser tabs
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { fastApiClient } from '@/services/fastApiClient';
import { 
  SecurityAlert, 
  WazuhAgent, 
  WazuhStatus, 
  GVMStatus, 
  ZAPStatus,
  WSMessage 
} from '@/types/security';
import { useToast } from '@/hooks/use-toast';

interface RealTimeSecurityState {
  // Service Status
  services: {
    wazuh: WazuhStatus;
    gvm: GVMStatus;
    zap: ZAPStatus;
  };
  
  // Real-time Data
  alerts: SecurityAlert[];
  agents: WazuhAgent[];
  
  // Connection State
  isConnected: boolean;
  isLoading: boolean;
  lastUpdate: string | null;
  error: string | null;
}

interface UseRealTimeSecurityDataReturn extends RealTimeSecurityState {
  // Actions
  refreshAll: () => Promise<void>;
  refreshService: (service: keyof RealTimeSecurityState['services']) => Promise<void>;
  acknowledgeAlert: (alertId: string) => Promise<void>;
  restartAgent: (agentId: string) => Promise<void>;
  
  // Stats
  getServiceStats: () => {
    totalServices: number;
    onlineServices: number;
    totalAgents: number;
    activeAgents: number;
    totalAlerts: number;
    criticalAlerts: number;
  };
}

export const useRealTimeSecurityData = (): UseRealTimeSecurityDataReturn => {
  const { toast } = useToast();
  const wsListenersRef = useRef<(() => void)[]>([]);
  
  const [state, setState] = useState<RealTimeSecurityState>({
    services: {
      wazuh: {
        online: false,
        lastCheck: null,
        error: null,
        responseTime: 0,
        retryCount: 0,
        agents: 0,
        activeAgents: 0,
        managerVersion: '',
        rulesLoaded: 0
      },
      gvm: {
        online: false,
        lastCheck: null,
        error: null,
        responseTime: 0,
        retryCount: 0,
        scans: 0,
        activeScans: 0,
        totalTasks: 0,
        vulnerabilities: 0
      },
      zap: {
        online: false,
        lastCheck: null,
        error: null,
        responseTime: 0,
        retryCount: 0,
        scans: 0,
        activeScans: 0,
        alerts: 0,
        spiderProgress: 0,
        activeScanProgress: 0
      }
    },
    alerts: [],
    agents: [],
    isConnected: false,
    isLoading: true,
    lastUpdate: null,
    error: null
  });

  /**
   * Handle WebSocket status updates
   */
  const handleStatusUpdate = useCallback((event: CustomEvent<WSMessage>) => {
    const { data } = event.detail;
    
    setState(prev => ({
      ...prev,
      services: {
        ...prev.services,
        [data.service]: {
          ...prev.services[data.service as keyof typeof prev.services],
          ...data.status,
          lastCheck: new Date().toISOString()
        }
      },
      lastUpdate: new Date().toISOString(),
      isConnected: true
    }));
  }, []);

  /**
   * Handle new security alerts
   */
  const handleNewAlert = useCallback((event: CustomEvent<WSMessage>) => {
    const alert = event.detail.data as SecurityAlert;
    
    setState(prev => ({
      ...prev,
      alerts: [alert, ...prev.alerts].slice(0, 100), // Keep last 100 alerts
      lastUpdate: new Date().toISOString()
    }));

    // Show toast notification for critical/high alerts
    if (['critical', 'high'].includes(alert.severity)) {
      toast({
        title: `${alert.severity.toUpperCase()} Alert`,
        description: `${alert.title} from ${alert.source}`,
        variant: alert.severity === 'critical' ? 'destructive' : 'default'
      });
    }
  }, [toast]);

  /**
   * Handle agent updates
   */
  const handleAgentUpdate = useCallback((event: CustomEvent<WSMessage>) => {
    const agentUpdate = event.detail.data;
    
    setState(prev => {
      const updatedAgents = [...prev.agents];
      const existingIndex = updatedAgents.findIndex(agent => agent.id === agentUpdate.id);
      
      if (existingIndex >= 0) {
        updatedAgents[existingIndex] = { ...updatedAgents[existingIndex], ...agentUpdate };
      } else {
        updatedAgents.push(agentUpdate);
      }
      
      return {
        ...prev,
        agents: updatedAgents,
        lastUpdate: new Date().toISOString()
      };
    });
  }, []);

  /**
   * Handle scan progress updates
   */
  const handleScanProgress = useCallback((event: CustomEvent<WSMessage>) => {
    const { service, scanId, progress, status } = event.detail.data;
    
    // Update service scan progress
    setState(prev => ({
      ...prev,
      services: {
        ...prev.services,
        [service]: {
          ...prev.services[service as keyof typeof prev.services],
          ...progress
        }
      },
      lastUpdate: new Date().toISOString()
    }));

    // Show completion notification
    if (status === 'completed') {
      toast({
        title: 'Scan Completed',
        description: `${service.toUpperCase()} scan ${scanId} has finished.`
      });
    }
  }, [toast]);

  /**
   * Initialize WebSocket event listeners
   */
  const initializeEventListeners = useCallback(() => {
    // Clean up existing listeners
    wsListenersRef.current.forEach(cleanup => cleanup());
    wsListenersRef.current = [];

    // Status updates
    const statusListener = (event: Event) => handleStatusUpdate(event as CustomEvent<WSMessage>);
    window.addEventListener('security:status', statusListener);
    wsListenersRef.current.push(() => window.removeEventListener('security:status', statusListener));

    // Alert updates
    const alertListener = (event: Event) => handleNewAlert(event as CustomEvent<WSMessage>);
    window.addEventListener('security:alert', alertListener);
    wsListenersRef.current.push(() => window.removeEventListener('security:alert', alertListener));

    // Agent updates
    const agentListener = (event: Event) => handleAgentUpdate(event as CustomEvent<WSMessage>);
    window.addEventListener('security:agent_update', agentListener);
    wsListenersRef.current.push(() => window.removeEventListener('security:agent_update', agentListener));

    // Scan progress updates
    const scanListener = (event: Event) => handleScanProgress(event as CustomEvent<WSMessage>);
    window.addEventListener('security:scan_progress', scanListener);
    wsListenersRef.current.push(() => window.removeEventListener('security:scan_progress', scanListener));

  }, [handleStatusUpdate, handleNewAlert, handleAgentUpdate, handleScanProgress]);

  /**
   * Refresh all service data via FastAPI client
   */
  const refreshAll = useCallback(async () => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    
    try {
      console.log('🔄 Refreshing security data via FastAPI');
      
      // Fetch agents
      const agentsResponse = await fastApiClient.getWazuhAgents();
      if (agentsResponse.success && agentsResponse.data) {
        setState(prev => ({
          ...prev,
          agents: agentsResponse.data as unknown as WazuhAgent[]
        }));
        console.log(`✅ Loaded ${agentsResponse.data.length} Wazuh agents`);
      }
      
      // Fetch alerts
      const alertsResponse = await fastApiClient.getWazuhAlerts(100);
      if (alertsResponse.success && alertsResponse.data) {
        const mappedAlerts: SecurityAlert[] = alertsResponse.data.map(alert => ({
          id: alert.id,
          source: 'wazuh' as const,
          timestamp: alert.timestamp,
          severity: alert.rule.level >= 12 ? 'critical' : 
                   alert.rule.level >= 8 ? 'high' :
                   alert.rule.level >= 5 ? 'medium' : 'low',
          title: alert.rule.description,
          description: alert.full_log,
          agentId: alert.agent.id,
          agentName: alert.agent.name,
          rule: {
            id: alert.rule.id.toString(),
            description: alert.rule.description,
            level: alert.rule.level
          },
          acknowledged: false
        }));
        
        setState(prev => ({
          ...prev,
          alerts: mappedAlerts
        }));
        console.log(`✅ Loaded ${mappedAlerts.length} security alerts`);
      }
      
      // Check health of all services
      const healthResponse = await fastApiClient.getServicesHealth();
      if (healthResponse.success && healthResponse.data) {
        console.log('✅ Services health checked');
      }
      
      setState(prev => ({
        ...prev,
        isLoading: false,
        lastUpdate: new Date().toISOString(),
        isConnected: true
      }));
      
    } catch (error) {
      console.error('❌ Failed to refresh security data:', error);
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to refresh data',
        isConnected: false
      }));
    }
  }, []);

  /**
   * Refresh specific service data via FastAPI
   */
  const refreshService = useCallback(async (service: keyof RealTimeSecurityState['services']) => {
    try {
      console.log(`🔄 Refreshing ${service} service via FastAPI`);
      
      const response = await fastApiClient.checkServiceHealth(service);
      
      if (response.success && response.data) {
        setState(prev => ({
          ...prev,
          services: {
            ...prev.services,
            [service]: { 
              ...prev.services[service],
              online: response.data.status === 'healthy',
              error: response.data.error || null,
              lastCheck: new Date().toISOString(),
              responseTime: response.data.responseTime
            }
          },
          lastUpdate: new Date().toISOString()
        }));
      }
    } catch (error) {
      console.error(`❌ Failed to refresh ${service} service:`, error);
      setState(prev => ({
        ...prev,
        services: {
          ...prev.services,
          [service]: { 
            ...prev.services[service],
            online: false,
            error: error instanceof Error ? error.message : 'Connection failed',
            lastCheck: new Date().toISOString()
          }
        }
      }));
    }
  }, []);

  /**
   * Acknowledge security alert
   */
  const acknowledgeAlert = useCallback(async (alertId: string) => {
    try {
      // Backend API call to acknowledge alert
      // await securityServicesApi.acknowledgeAlert(alertId);
      
      setState(prev => ({
        ...prev,
        alerts: prev.alerts.map(alert =>
          alert.id === alertId ? { ...alert, acknowledged: true } : alert
        )
      }));

      toast({
        title: 'Alert Acknowledged',
        description: 'Alert has been marked as acknowledged.'
      });

    } catch (error) {
      console.error('❌ Failed to acknowledge alert:', error);
      toast({
        title: 'Error',
        description: 'Failed to acknowledge alert.',
        variant: 'destructive'
      });
    }
  }, [toast]);

  /**
   * Restart Wazuh agent via FastAPI
   */
  const restartAgent = useCallback(async (agentId: string) => {
    try {
      console.log(`🔄 Restarting agent ${agentId} via FastAPI`);
      
      const response = await fastApiClient.restartWazuhAgent(agentId, false);
      
      if (response.success) {
        toast({
          title: 'Agent Restart',
          description: response.data?.message || `Agent ${agentId} restart initiated.`
        });
      } else {
        throw new Error(response.error || 'Failed to restart agent');
      }

    } catch (error) {
      console.error('❌ Failed to restart agent:', error);
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to restart agent.',
        variant: 'destructive'
      });
    }
  }, [toast]);

  /**
   * Get service statistics
   */
  const getServiceStats = useCallback(() => {
    const services = Object.values(state.services);
    const onlineServices = services.filter(s => s.online).length;
    const totalAgents = state.agents.length;
    const activeAgents = state.agents.filter(a => a.status === 'active').length;
    const totalAlerts = state.alerts.length;
    const criticalAlerts = state.alerts.filter(a => a.severity === 'critical').length;

    return {
      totalServices: services.length,
      onlineServices,
      totalAgents,
      activeAgents,
      totalAlerts,
      criticalAlerts
    };
  }, [state]);

  /**
   * Initialize hook
   */
  useEffect(() => {
    initializeEventListeners();
    refreshAll();

    // Set up periodic refresh (every 30 seconds)
    const refreshInterval = setInterval(refreshAll, 30000);

    // Cleanup
    return () => {
      clearInterval(refreshInterval);
      wsListenersRef.current.forEach(cleanup => cleanup());
    };
  }, [initializeEventListeners, refreshAll]);

  return {
    ...state,
    refreshAll,
    refreshService,
    acknowledgeAlert,
    restartAgent,
    getServiceStats
  };
};