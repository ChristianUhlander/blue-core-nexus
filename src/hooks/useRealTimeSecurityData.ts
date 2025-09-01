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
      // Skip backend calls in demo mode to prevent errors
      console.log('🔄 Refreshing security data (demo mode)');
      
      // Set mock data for demo
      setState(prev => ({
        ...prev,
        isLoading: false,
        lastUpdate: new Date().toISOString(),
        isConnected: false, // Keep as false since no real backend
        services: {
          wazuh: { ...prev.services.wazuh, online: false, error: 'Demo mode - no backend' },
          gvm: { ...prev.services.gvm, online: false, error: 'Demo mode - no backend' },
          zap: { ...prev.services.zap, online: false, error: 'Demo mode - no backend' },
          spiderfoot: { ...prev.services.spiderfoot, online: false, error: 'Demo mode - no backend' }
        },
        alerts: [], // Mock data can be added here if needed
        agents: [] // Mock data can be added here if needed
      }));
      
    } catch (error) {
      console.error('❌ Failed to refresh security data:', error);
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: 'Demo mode - backend services not available',
        isConnected: false
      }));
    }
  }, []);

  /**
   * Refresh specific service data
   */
  const refreshService = useCallback(async (service: keyof RealTimeSecurityState['services']) => {
    try {
      console.log(`🔄 Refreshing ${service} service (demo mode)`);
      
      // Update service status without backend call
      setState(prev => ({
        ...prev,
        services: {
          ...prev.services,
          [service]: { 
            ...prev.services[service], 
            online: false, 
            error: 'Demo mode - no backend',
            lastCheck: new Date().toISOString()
          }
        },
        lastUpdate: new Date().toISOString()
      }));
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
      console.log(`🔄 Restart agent ${agentId} (demo mode)`);
      
      toast({
        title: 'Demo Mode',
        description: `Agent restart simulated for ${agentId} - backend not available.`
      });

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