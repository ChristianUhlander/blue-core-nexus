/**
 * K8s Security API Service
 * Real integration with security tools deployed in Kubernetes cluster
 * 
 * BACKEND DEPLOYMENT REQUIREMENTS:
 * 1. Wazuh Manager: deployed as StatefulSet with persistent volume
 * 2. OpenVAS/GVM: deployed with Redis and PostgreSQL dependencies  
 * 3. OWASP ZAP: deployed as Deployment with headless service
 * 4. Spiderfoot: deployed with SQLite persistence
 * 5. All services exposed via K8s Services with proper networking
 * 
 * SECURITY CONSIDERATIONS:
 * - All API calls use service discovery (service-name.namespace.svc.cluster.local)
 * - Authentication tokens stored as K8s Secrets
 * - Network policies restrict inter-service communication
 * - TLS termination at ingress level
 */

import { 
  ServiceConfig, 
  ConnectionStatus, 
  WazuhStatus, 
  GVMStatus, 
  ZAPStatus, 
  SpiderfootStatus,
  SecurityAlert,
  WazuhAgent,
  ScanResult,
  ApiResponse,
  WSMessage,
  K8sServiceEndpoint
} from '@/types/security';

// K8s Service Configuration
const K8S_SERVICES: Record<string, K8sServiceEndpoint> = {
  wazuh: {
    namespace: 'security',
    serviceName: 'wazuh-manager',
    port: 55000,
    path: '/security/user/authenticate'
  },
  gvm: {
    namespace: 'security', 
    serviceName: 'openvas-gvm',
    port: 9392,
    path: '/gmp'
  },
  zap: {
    namespace: 'security',
    serviceName: 'owasp-zap',
    port: 8080,
    path: '/JSON/core/view/version'
  },
  spiderfoot: {
    namespace: 'security',
    serviceName: 'spiderfoot-osint',
    port: 5001,
    path: '/api'
  }
};

class K8sSecurityApiService {
  private baseUrl: string;
  private wsConnection: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private apiKeys: Record<string, string> = {};

  constructor() {
    // In K8s environment, use service discovery
    // Format: http://service-name.namespace.svc.cluster.local:port
    this.baseUrl = process.env.NODE_ENV === 'production' 
      ? 'https://security-api.security.svc.cluster.local'
      : 'http://localhost:3001'; // Development fallback
    
    this.initializeApiKeys();
    this.initializeWebSocket();
  }

  /**
   * Initialize API keys from environment variables or K8s secrets
   * Backend: Mount secrets as environment variables in deployment
   */
  private initializeApiKeys() {
    this.apiKeys = {
      wazuh: process.env.WAZUH_API_KEY || '',
      gvm: process.env.GVM_API_KEY || '',
      zap: process.env.ZAP_API_KEY || '',
      spiderfoot: process.env.SPIDERFOOT_API_KEY || ''
    };
  }

  /**
   * Initialize WebSocket connection for real-time updates
   * Backend: WebSocket endpoint at /ws for real-time data streaming
   */
  private initializeWebSocket() {
    const wsUrl = this.baseUrl.replace('http', 'ws') + '/ws';
    
    try {
      this.wsConnection = new WebSocket(wsUrl);
      
      this.wsConnection.onopen = () => {
        console.log('🔌 WebSocket connected to security services');
        this.reconnectAttempts = 0;
      };
      
      this.wsConnection.onmessage = (event) => {
        try {
          const message: WSMessage = JSON.parse(event.data);
          this.handleWebSocketMessage(message);
        } catch (error) {
          console.error('❌ Failed to parse WebSocket message:', error);
        }
      };
      
      this.wsConnection.onclose = () => {
        console.log('🔌 WebSocket disconnected');
        this.scheduleReconnect();
      };
      
      this.wsConnection.onerror = (error) => {
        console.error('❌ WebSocket error:', error);
      };
      
    } catch (error) {
      console.error('❌ Failed to initialize WebSocket:', error);
    }
  }

  /**
   * Handle incoming WebSocket messages
   */
  private handleWebSocketMessage(message: WSMessage) {
    // Dispatch custom events for different message types
    const event = new CustomEvent(`security:${message.type}`, {
      detail: message
    });
    window.dispatchEvent(event);
  }

  /**
   * Schedule WebSocket reconnection with exponential backoff
   */
  private scheduleReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      const delay = Math.pow(2, this.reconnectAttempts) * 1000; // Exponential backoff
      
      setTimeout(() => {
        console.log(`🔄 Attempting WebSocket reconnection (${this.reconnectAttempts + 1}/${this.maxReconnectAttempts})`);
        this.reconnectAttempts++;
        this.initializeWebSocket();
      }, delay);
    }
  }

  /**
   * Generic API request handler with retry logic and timeout
   */
  private async makeRequest<T>(
    endpoint: string,
    options: RequestInit = {},
    timeout = 10000,
    retries = 3
  ): Promise<ApiResponse<T>> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const requestOptions: RequestInit = {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': crypto.randomUUID(),
        ...options.headers
      }
    };

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const response = await fetch(`${this.baseUrl}${endpoint}`, requestOptions);
        clearTimeout(timeoutId);

        const data = await response.json();
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${data.error || response.statusText}`);
        }

        return {
          success: true,
          data: data,
          timestamp: new Date().toISOString(),
          requestId: requestOptions.headers!['X-Request-ID'] as string
        };

      } catch (error) {
        clearTimeout(timeoutId);
        
        if (attempt === retries) {
          console.error(`❌ API request failed after ${retries + 1} attempts:`, error);
          return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error',
            timestamp: new Date().toISOString(),
            requestId: requestOptions.headers!['X-Request-ID'] as string
          };
        }
        
        // Wait before retry with exponential backoff
        await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
      }
    }

    throw new Error('Request failed after all retries');
  }

  /**
   * Health check for all services
   * Backend Endpoint: GET /api/health/all
   */
  async checkAllServicesHealth(): Promise<ApiResponse<{
    wazuh: WazuhStatus;
    gvm: GVMStatus;
    zap: ZAPStatus;
    spiderfoot: SpiderfootStatus;
  }>> {
    return this.makeRequest('/api/health/all');
  }

  /**
   * Check specific service health
   * Backend Endpoint: GET /api/health/{service}
   */
  async checkServiceHealth(service: 'wazuh' | 'gvm' | 'zap' | 'spiderfoot'): Promise<ApiResponse<ConnectionStatus>> {
    return this.makeRequest(`/api/health/${service}`);
  }

  /**
   * Wazuh SIEM Integration
   * Backend Endpoint: GET /api/wazuh/agents
   */
  async getWazuhAgents(): Promise<ApiResponse<WazuhAgent[]>> {
    return this.makeRequest('/api/wazuh/agents', {
      headers: {
        'Authorization': `Bearer ${this.apiKeys.wazuh}`
      }
    });
  }

  /**
   * Get Wazuh alerts with filtering
   * Backend Endpoint: GET /api/wazuh/alerts
   */
  async getWazuhAlerts(params: {
    limit?: number;
    offset?: number;
    severity?: string;
    agentId?: string;
    timeRange?: string;
  }): Promise<ApiResponse<SecurityAlert[]>> {
    const queryParams = new URLSearchParams(params as Record<string, string>);
    return this.makeRequest(`/api/wazuh/alerts?${queryParams}`, {
      headers: {
        'Authorization': `Bearer ${this.apiKeys.wazuh}`
      }
    });
  }

  /**
   * Restart Wazuh agent
   * Backend Endpoint: POST /api/wazuh/agents/{agentId}/restart
   */
  async restartWazuhAgent(agentId: string): Promise<ApiResponse<{ message: string }>> {
    return this.makeRequest(`/api/wazuh/agents/${agentId}/restart`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.apiKeys.wazuh}`
      }
    });
  }

  /**
   * OpenVAS/GVM Integration
   * Backend Endpoint: POST /api/gvm/scans
   */
  async startGVMScan(config: {
    name: string;
    target: string;
    scanType: string;
    options?: Record<string, any>;
  }): Promise<ApiResponse<{ scanId: string; taskId: string }>> {
    return this.makeRequest('/api/gvm/scans', {
      method: 'POST',
      body: JSON.stringify(config),
      headers: {
        'Authorization': `Bearer ${this.apiKeys.gvm}`
      }
    });
  }

  /**
   * Get GVM scan results
   * Backend Endpoint: GET /api/gvm/scans/{scanId}/results
   */
  async getGVMScanResults(scanId: string): Promise<ApiResponse<ScanResult>> {
    return this.makeRequest(`/api/gvm/scans/${scanId}/results`, {
      headers: {
        'Authorization': `Bearer ${this.apiKeys.gvm}`
      }
    });
  }

  /**
   * OWASP ZAP Integration
   * Backend Endpoint: POST /api/zap/scans
   */
  async startZAPScan(config: {
    target: string;
    scanType: 'baseline' | 'full' | 'api';
    options?: {
      spider?: boolean;
      activeScan?: boolean;
      auth?: { url: string; username: string; password: string };
      exclude?: string[];
    };
  }): Promise<ApiResponse<{ scanId: string }>> {
    return this.makeRequest('/api/zap/scans', {
      method: 'POST',
      body: JSON.stringify(config),
      headers: {
        'Authorization': `Bearer ${this.apiKeys.zap}`
      }
    });
  }

  /**
   * Get ZAP scan progress
   * Backend Endpoint: GET /api/zap/scans/{scanId}/progress
   */
  async getZAPScanProgress(scanId: string): Promise<ApiResponse<{
    status: string;
    progress: number;
    alerts: number;
  }>> {
    return this.makeRequest(`/api/zap/scans/${scanId}/progress`, {
      headers: {
        'Authorization': `Bearer ${this.apiKeys.zap}`
      }
    });
  }

  /**
   * Spiderfoot OSINT Integration
   * Backend Endpoint: POST /api/spiderfoot/scans
   */
  async startSpiderfootScan(config: {
    target: string;
    scanType: string;
    modules: string[];
  }): Promise<ApiResponse<{ scanId: string }>> {
    return this.makeRequest('/api/spiderfoot/scans', {
      method: 'POST',
      body: JSON.stringify(config),
      headers: {
        'Authorization': `Bearer ${this.apiKeys.spiderfoot}`
      }
    });
  }

  /**
   * Get Spiderfoot scan results
   * Backend Endpoint: GET /api/spiderfoot/scans/{scanId}/results
   */
  async getSpiderfootResults(scanId: string): Promise<ApiResponse<any[]>> {
    return this.makeRequest(`/api/spiderfoot/scans/${scanId}/results`, {
      headers: {
        'Authorization': `Bearer ${this.apiKeys.spiderfoot}`
      }
    });
  }

  /**
   * QA Validation Methods
   */
  
  /**
   * Validate service configuration
   */
  validateServiceConfig(config: ServiceConfig): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    if (!config.name?.trim()) errors.push('Service name is required');
    if (!config.endpoint?.trim()) errors.push('Service endpoint is required');
    if (!['http', 'https', 'ws', 'wss'].includes(config.protocol)) {
      errors.push('Invalid protocol, must be http, https, ws, or wss');
    }
    if (!config.port || config.port < 1 || config.port > 65535) {
      errors.push('Port must be between 1 and 65535');
    }
    if (config.timeout < 1000) errors.push('Timeout must be at least 1000ms');
    if (config.retryAttempts < 0 || config.retryAttempts > 10) {
      errors.push('Retry attempts must be between 0 and 10');
    }
    
    return { valid: errors.length === 0, errors };
  }

  /**
   * Test connectivity to all services
   */
  async runConnectivityTests(): Promise<Record<string, {
    success: boolean;
    responseTime: number;
    error?: string;
  }>> {
    const services = ['wazuh', 'gvm', 'zap', 'spiderfoot'];
    const results: Record<string, any> = {};
    
    await Promise.allSettled(
      services.map(async (service) => {
        const startTime = Date.now();
        try {
          const response = await this.checkServiceHealth(service as any);
          results[service] = {
            success: response.success,
            responseTime: Date.now() - startTime,
            error: response.error
          };
        } catch (error) {
          results[service] = {
            success: false,
            responseTime: Date.now() - startTime,
            error: error instanceof Error ? error.message : 'Unknown error'
          };
        }
      })
    );
    
    return results;
  }

  /**
   * Cleanup resources
   */
  cleanup() {
    if (this.wsConnection) {
      this.wsConnection.close();
      this.wsConnection = null;
    }
  }
}

// Export singleton instance
export const k8sSecurityApi = new K8sSecurityApiService();

// Cleanup on page unload
if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', () => {
    k8sSecurityApi.cleanup();
  });
}