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
  requestId?: string;
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
  async getWazuhAgents(limit?: number, sort?: string): Promise<ApiResponse<WazuhAgent[]>> {
    const params = new URLSearchParams();
    if (limit) params.append('limit', limit.toString());
    if (sort) params.append('sort', sort);
    
    const queryString = params.toString();
    const url = `${this.baseUrl}/api/wazuh/agents${queryString ? `?${queryString}` : ''}`;
    
    return this.makeRequest<WazuhAgent[]>(url);
  }

  async getWazuhAlerts(limit = 50): Promise<ApiResponse<WazuhAlert[]>> {
    return this.makeRequest<WazuhAlert[]>(`${this.baseUrl}/api/wazuh/alerts?limit=${limit}`);
  }

  async searchWazuhAlerts(query: {
    size?: number;
    sort?: string;
    search?: string;
    rule_id?: number;
    agent_id?: string;
    level?: number;
  }): Promise<ApiResponse<WazuhAlert[]>> {
    return this.makeRequest<WazuhAlert[]>(`${this.baseUrl}/api/wazuh/alerts/search`, {
      method: 'POST',
      body: JSON.stringify(query),
    });
  }

  async restartWazuhAgent(agentId: string, waitForComplete = false): Promise<ApiResponse<{
    status: string;
    message: string;
  }>> {
    return this.makeRequest(`${this.baseUrl}/api/wazuh/agents/${agentId}/restart`, {
      method: 'PUT',
      body: JSON.stringify({ wait_for_complete: waitForComplete }),
    });
  }

  async searchWazuhVulnerabilities(query: {
    agent_id?: string;
    cve?: string;
    severity?: string;
    status?: string;
  }): Promise<ApiResponse<any[]>> {
    return this.makeRequest(`${this.baseUrl}/api/wazuh/vulnerabilities/search`, {
      method: 'POST',
      body: JSON.stringify(query),
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
  async listGvmTargets(): Promise<ApiResponse<any[]>> {
    return this.makeRequest(`${this.baseUrl}/api/gvm/targets`);
  }

  async createGvmTarget(target: {
    name: string;
    hosts: string[];
    port_list_id?: string;
    comment?: string;
  }): Promise<ApiResponse<{ id: string }>> {
    return this.makeRequest(`${this.baseUrl}/api/gvm/targets`, {
      method: 'POST',
      body: JSON.stringify(target),
    });
  }

  async deleteGvmTarget(targetId: string): Promise<ApiResponse<void>> {
    return this.makeRequest(`${this.baseUrl}/api/gvm/targets/${targetId}`, {
      method: 'DELETE',
    });
  }

  async listGvmTasks(): Promise<ApiResponse<any[]>> {
    return this.makeRequest(`${this.baseUrl}/api/gvm/tasks`);
  }

  async createGvmTask(task: {
    name: string;
    target_id: string;
    config_id: string;
    scanner_id?: string;
    comment?: string;
  }): Promise<ApiResponse<{ id: string }>> {
    return this.makeRequest(`${this.baseUrl}/api/gvm/tasks`, {
      method: 'POST',
      body: JSON.stringify(task),
    });
  }

  async startGvmTask(taskId: string): Promise<ApiResponse<{ report_id: string }>> {
    return this.makeRequest(`${this.baseUrl}/api/gvm/tasks/${taskId}/start`, {
      method: 'POST',
    });
  }

  async getGvmReport(reportId: string, format: 'xml' | 'pdf' | 'html' = 'xml'): Promise<ApiResponse<any>> {
    return this.makeRequest(`${this.baseUrl}/api/gvm/reports/${reportId}?format=${format}`);
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