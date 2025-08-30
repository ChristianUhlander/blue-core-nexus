/**
 * Production-Ready FastAPI Client
 * Handles all communication with FastAPI backend services
 */

import { config, logger } from '@/config/environment';

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  timestamp: string;
}

export interface WazuhAgent {
  id: string;
  name: string;
  ip: string;
  status: 'active' | 'disconnected' | 'pending' | 'never_connected';
  os: {
    platform: string;
    version: string;
    name: string;
  };
  version: string;
  lastKeepAlive: string;
  group: string[];
  node_name: string;
}

export interface WazuhAlert {
  id: string;
  timestamp: string;
  rule: {
    id: number;
    level: number;
    description: string;
    groups: string[];
  };
  agent: {
    id: string;
    name: string;
    ip: string;
  };
  location: string;
  full_log: string;
  decoder: {
    name: string;
  };
}

export interface ServiceHealth {
  service: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  lastCheck: string;
  responseTime: number;
  error?: string;
  version?: string;
}

class FastApiClient {
  private baseUrl: string;
  private timeout: number;

  constructor() {
    this.baseUrl = config.api.baseUrl;
    this.timeout = config.api.timeout;
  }

  private async makeRequest<T>(
    url: string,
    options: RequestInit = {},
    retryAttempts = 3,
    retryDelay = 2000
  ): Promise<ApiResponse<T>> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    const requestOptions: RequestInit = {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    };

    for (let attempt = 1; attempt <= retryAttempts; attempt++) {
      try {
        logger.debug(`API Request [Attempt ${attempt}]:`, url, requestOptions);

        const response = await fetch(url, requestOptions);
        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        
        logger.debug(`API Response [Success]:`, url, data);
        
        return {
          success: true,
          data,
          timestamp: new Date().toISOString(),
        };

      } catch (error) {
        logger.warn(`API Request [Attempt ${attempt}] Failed:`, url, error);

        if (attempt === retryAttempts) {
          clearTimeout(timeoutId);
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          
          logger.error(`API Request [Failed]:`, url, errorMessage);
          
          return {
            success: false,
            error: errorMessage,
            message: `Failed to connect to ${url} after ${retryAttempts} attempts`,
            timestamp: new Date().toISOString(),
          };
        }

        // Wait before retry (exponential backoff)
        await new Promise(resolve => setTimeout(resolve, retryDelay * attempt));
      }
    }

    // This should never be reached, but TypeScript requires it
    return {
      success: false,
      error: 'Unexpected error in retry logic',
      timestamp: new Date().toISOString(),
    };
  }

  // Wazuh API Methods
  async getWazuhAgents(): Promise<ApiResponse<WazuhAgent[]>> {
    return this.makeRequest<WazuhAgent[]>(`${this.baseUrl}/api/wazuh/agents`);
  }

  async getWazuhAlerts(limit = 50): Promise<ApiResponse<WazuhAlert[]>> {
    return this.makeRequest<WazuhAlert[]>(`${this.baseUrl}/api/wazuh/alerts?limit=${limit}`);
  }

  async restartWazuhAgent(agentId: string): Promise<ApiResponse<void>> {
    return this.makeRequest(`${this.baseUrl}/api/wazuh/agents/${agentId}/restart`, {
      method: 'POST',
    });
  }

  // Health Check Methods
  async getServicesHealth(): Promise<ApiResponse<ServiceHealth[]>> {
    return this.makeRequest<ServiceHealth[]>(`${this.baseUrl}/api/health/all`);
  }

  async checkServiceHealth(service: string): Promise<ApiResponse<ServiceHealth>> {
    return this.makeRequest<ServiceHealth>(`${this.baseUrl}/api/health/${service}`);
  }

  // GVM/OpenVAS Methods
  async getGvmTasks(): Promise<ApiResponse<any[]>> {
    return this.makeRequest<any[]>(`${this.baseUrl}/api/gvm/tasks`);
  }

  async startGvmScan(taskId: string): Promise<ApiResponse<any>> {
    return this.makeRequest(`${this.baseUrl}/api/gvm/tasks/${taskId}/start`, {
      method: 'POST',
    });
  }

  // OWASP ZAP Methods
  async getZapVersion(): Promise<ApiResponse<any>> {
    return this.makeRequest(`${this.baseUrl}/api/zap/version`);
  }

  async startZapScan(target: string, scanType: string): Promise<ApiResponse<any>> {
    return this.makeRequest(`${this.baseUrl}/api/zap/scan`, {
      method: 'POST',
      body: JSON.stringify({ target, scanType }),
    });
  }

  // SpiderFoot Methods
  async getSpiderfootScans(): Promise<ApiResponse<any[]>> {
    return this.makeRequest<any[]>(`${this.baseUrl}/api/spiderfoot/scans`);
  }

  async startSpiderfootScan(target: string, scanType: string, modules: string[]): Promise<ApiResponse<any>> {
    return this.makeRequest(`${this.baseUrl}/api/spiderfoot/scan`, {
      method: 'POST',
      body: JSON.stringify({ target, scanType, modules }),
    });
  }

  // WebSocket Connection
  connectWebSocket(): WebSocket | null {
    try {
      const ws = new WebSocket(config.websocket.url);
      
      ws.onopen = () => {
        logger.info('WebSocket connected successfully');
      };
      
      ws.onclose = () => {
        logger.warn('WebSocket connection closed');
        // Auto-reconnect logic could be added here
      };
      
      ws.onerror = (error) => {
        logger.error('WebSocket error:', error);
      };

      return ws;
    } catch (error) {
      logger.error('Failed to create WebSocket connection:', error);
      return null;
    }
  }
}

// Export singleton instance
export const fastApiClient = new FastApiClient();

// Mock data for development when backend is unavailable
export const mockData = {
  agents: [
    {
      id: '001',
      name: 'web-server-01',
      ip: '192.168.1.100',
      status: 'active' as const,
      os: { platform: 'ubuntu', version: '20.04', name: 'Ubuntu' },
      version: '4.3.10',
      lastKeepAlive: new Date().toISOString(),
      group: ['default', 'web-servers'],
      node_name: 'node01',
    },
    {
      id: '002', 
      name: 'db-server-01',
      ip: '192.168.1.101',
      status: 'active' as const,
      os: { platform: 'centos', version: '8', name: 'CentOS' },
      version: '4.3.10',
      lastKeepAlive: new Date().toISOString(),
      group: ['default', 'database'],
      node_name: 'node01',
    },
    {
      id: '003',
      name: 'app-server-01', 
      ip: '192.168.1.102',
      status: 'disconnected' as const,
      os: { platform: 'windows', version: '2019', name: 'Windows Server' },
      version: '4.3.10',
      lastKeepAlive: new Date(Date.now() - 300000).toISOString(),
      group: ['default', 'applications'],
      node_name: 'node02',
    },
  ] as WazuhAgent[],

  alerts: [
    {
      id: 'alert_001',
      timestamp: new Date().toISOString(),
      rule: {
        id: 5710,
        level: 5,
        description: 'Attempt to login using a non-existent user',
        groups: ['authentication_failed', 'pci_dss_10.2.4'],
      },
      agent: { id: '001', name: 'web-server-01', ip: '192.168.1.100' },
      location: '/var/log/auth.log',
      full_log: 'Jan 30 09:54:35 web-server-01 sshd[1234]: Failed password for invalid user admin from 192.168.1.200 port 22 ssh2',
      decoder: { name: 'sshd' },
    },
    {
      id: 'alert_002',
      timestamp: new Date(Date.now() - 120000).toISOString(),
      rule: {
        id: 31151,
        level: 10,
        description: 'Multiple authentication failures',
        groups: ['authentication_failures', 'pci_dss_11.4'],
      },
      agent: { id: '002', name: 'db-server-01', ip: '192.168.1.101' },
      location: '/var/log/secure',
      full_log: 'Jan 30 09:52:15 db-server-01 sshd[5678]: Failed password for root from 10.0.0.50 port 22 ssh2',
      decoder: { name: 'sshd' },
    },
  ] as WazuhAlert[],

  serviceHealth: [
    {
      service: 'wazuh',
      status: 'unhealthy' as const,
      lastCheck: new Date().toISOString(),
      responseTime: 0,
      error: 'Connection refused',
    },
    {
      service: 'gvm',
      status: 'unhealthy' as const,
      lastCheck: new Date().toISOString(),
      responseTime: 0,
      error: 'Service unavailable',
    },
    {
      service: 'zap',
      status: 'unhealthy' as const,
      lastCheck: new Date().toISOString(),
      responseTime: 0,
      error: 'Connection timeout',
    },
    {
      service: 'spiderfoot',
      status: 'unhealthy' as const,
      lastCheck: new Date().toISOString(),
      responseTime: 0,
      error: 'Service not running',
    },
  ] as ServiceHealth[],
};