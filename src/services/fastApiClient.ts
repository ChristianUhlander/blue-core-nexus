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
  serviceHealth: [
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