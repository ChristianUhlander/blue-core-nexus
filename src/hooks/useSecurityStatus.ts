/**
 * Security Status Management Hook
 * 
 * This hook manages the connection status of all security services
 * and provides real-time updates on their availability.
 * 
 * Features:
 * - Real-time connection monitoring
 * - Automatic retry logic
 * - Connection health indicators
 * - Service metrics tracking
 * 
 * @author Security Dashboard Team
 * @version 1.0.0
 */

import { useState, useEffect, useCallback } from 'react';
import { ApiConnectionStatus, securityApiManager } from '@/services/securityApi';

export interface SecurityStatusState {
  statuses: Map<string, ApiConnectionStatus>;
  isLoading: boolean;
  error: string | null;
  lastUpdate: Date | null;
}

export const useSecurityStatus = () => {
  const [state, setState] = useState<SecurityStatusState>({
    statuses: new Map(),
    isLoading: false,
    error: null,
    lastUpdate: null
  });

  /**
   * Check connection status for a specific service
   * @param serviceName - Name of the service to check
   */
  const checkServiceConnection = useCallback(async (serviceName: string) => {
    try {
      const service = securityApiManager.getService(serviceName);
      if (!service) {
        throw new Error(`Service '${serviceName}' not found`);
      }

      const status = await service.checkConnection();
      
      setState(prev => ({
        ...prev,
        statuses: new Map(prev.statuses.set(serviceName, status)),
        lastUpdate: new Date(),
        error: null
      }));

      return status;
    } catch (error) {
      const errorStatus: ApiConnectionStatus = {
        service: serviceName,
        connected: false,
        lastChecked: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error'
      };

      setState(prev => ({
        ...prev,
        statuses: new Map(prev.statuses.set(serviceName, errorStatus)),
        lastUpdate: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error'
      }));

      return errorStatus;
    }
  }, []);

  /**
   * Check all service connections
   */
  const checkAllConnections = useCallback(async () => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const statuses = await securityApiManager.checkAllConnections();
      const statusMap = new Map();
      
      statuses.forEach(status => {
        const serviceName = status.service.toLowerCase().replace(/[^a-z]/g, '');
        statusMap.set(serviceName, status);
      });

      setState(prev => ({
        ...prev,
        statuses: statusMap,
        isLoading: false,
        lastUpdate: new Date(),
        error: null
      }));
    } catch (error) {
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to check connections'
      }));
    }
  }, []);

  /**
   * Get status for a specific service
   * @param serviceName - Name of the service
   * @returns ApiConnectionStatus or null
   */
  const getServiceStatus = useCallback((serviceName: string): ApiConnectionStatus | null => {
    return state.statuses.get(serviceName) || null;
  }, [state.statuses]);

  /**
   * Get connection indicator color based on status
   * @param serviceName - Name of the service
   * @returns string - CSS color class
   */
  const getConnectionIndicator = useCallback((serviceName: string): {
    color: string;
    status: 'connected' | 'error' | 'unknown';
    message: string;
  } => {
    const status = getServiceStatus(serviceName);
    
    if (!status) {
      return {
        color: 'bg-gray-500',
        status: 'unknown',
        message: 'Status unknown'
      };
    }

    if (status.connected) {
      return {
        color: 'bg-green-500 animate-pulse-glow',
        status: 'connected',
        message: `Connected (${status.latency}ms)`
      };
    } else {
      return {
        color: 'bg-red-500 animate-pulse',
        status: 'error',
        message: status.error || 'Connection failed'
      };
    }
  }, [getServiceStatus]);

  /**
   * Initialize connection checks on mount
   */
  useEffect(() => {
    checkAllConnections();
    
    // Set up periodic health checks every 30 seconds
    const interval = setInterval(checkAllConnections, 30000);
    
    return () => clearInterval(interval);
  }, [checkAllConnections]);

  return {
    ...state,
    checkServiceConnection,
    checkAllConnections,
    getServiceStatus,
    getConnectionIndicator,
    
    // Computed values
    connectedServices: Array.from(state.statuses.values()).filter(s => s.connected).length,
    totalServices: state.statuses.size,
    hasErrors: Array.from(state.statuses.values()).some(s => !s.connected),
  };
};