/**
 * Real-time Security Data Hook
 * Manages WebSocket connections and real-time updates from K8s security services
 * 
 * BACKEND INTEGRATION:
 * - WebSocket server at /ws endpoint
 * - Real-time event streaming from security tools
 * - Automatic reconnection and error handling
 * - State synchronization across multiple browser tabs
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { k8sSecurityApi } from '@/services/k8sSecurityApi';
import { 
  SecurityAlert, 
  WazuhAgent, 
  WazuhStatus, 
  GVMStatus, 
  ZAPStatus, 
  SpiderfootStatus,
  WSMessage 
} from '@/types/security';
import { useToast } from '@/hooks/use-toast';

interface RealTimeSecurityState {
  // Service Status
  services: {
    wazuh: WazuhStatus;
    gvm: GVMStatus;
    zap: ZAPStatus;
    spiderfoot: SpiderfootStatus;
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
      },
      spiderfoot: {
        online: false,
        lastCheck: null,
        error: null,
        responseTime: 0,
        retryCount: 0,
        sources: 0,
        activeSources: 0,
        entities: 0,
        modules: 0
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
   * Refresh all service data
   */
  const refreshAll = useCallback(async () => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    
    try {
      // Parallel requests for better performance
      const [healthResponse, alertsResponse, agentsResponse] = await Promise.allSettled([
        k8sSecurityApi.checkAllServicesHealth(),
        k8sSecurityApi.getWazuhAlerts({ limit: 50 }),
        k8sSecurityApi.getWazuhAgents()
      ]);

      setState(prev => {
        const newState = { ...prev, isLoading: false, lastUpdate: new Date().toISOString() };

        // Update service health
        if (healthResponse.status === 'fulfilled' && healthResponse.value.success) {
          newState.services = { ...prev.services, ...healthResponse.value.data };
          newState.isConnected = true;
        }

        // Update alerts
        if (alertsResponse.status === 'fulfilled' && alertsResponse.value.success) {
          newState.alerts = alertsResponse.value.data || [];
        }

        // Update agents
        if (agentsResponse.status === 'fulfilled' && agentsResponse.value.success) {
          newState.agents = agentsResponse.value.data || [];
        }

        return newState;
      });

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
   * Refresh specific service data
   */
  const refreshService = useCallback(async (service: keyof RealTimeSecurityState['services']) => {
    try {
      const response = await k8sSecurityApi.checkServiceHealth(service);
      
      if (response.success) {
        setState(prev => ({
          ...prev,
          services: {
            ...prev.services,
            [service]: { ...prev.services[service], ...response.data }
          },
          lastUpdate: new Date().toISOString()
        }));
      }
    } catch (error) {
      console.error(`❌ Failed to refresh ${service} service:`, error);
    }
  }, []);

  /**
   * Acknowledge security alert
   */
  const acknowledgeAlert = useCallback(async (alertId: string) => {
    try {
      // Backend API call to acknowledge alert
      // await k8sSecurityApi.acknowledgeAlert(alertId);
      
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
   * Restart Wazuh agent
   */
  const restartAgent = useCallback(async (agentId: string) => {
    try {
      const response = await k8sSecurityApi.restartWazuhAgent(agentId);
      
      if (response.success) {
        toast({
          title: 'Agent Restart Initiated',
          description: `Restart command sent to agent ${agentId}.`
        });
      } else {
        throw new Error(response.error || 'Failed to restart agent');
      }

    } catch (error) {
      console.error('❌ Failed to restart agent:', error);
      toast({
        title: 'Error',
        description: 'Failed to restart agent.',
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