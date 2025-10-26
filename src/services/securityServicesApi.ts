/**
 * Security Services API Client
 * HTTP API client for security tools (Wazuh, GVM, ZAP)
 * 
 * FEATURES:
 * - HTTP request handling with retry logic and timeout
 * - WebSocket connection for real-time security alerts
 * - API key authentication for each service
 * - Health checks and service status monitoring
 * - Exponential backoff for reconnection
 */

import { 
  ServiceConfig, 
  ConnectionStatus, 
  GVMStatus,
  SecurityAlert,
  ScanResult,
  ApiResponse,
  WSMessage,
  ServiceEndpoint
} from '@/types/security';

// Service endpoint configuration
const SERVICE_ENDPOINTS: Record<string, ServiceEndpoint> = {
  gvm: {
    namespace: 'security', 
    serviceName: 'openvas-gvm',
    port: 9392,
    path: '/gmp'
  }
};

class SecurityServicesApiClient {
  private baseUrl: string;
  private wsConnection: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private apiKeys: Record<string, string> = {};

  constructor() {
    // Browser-safe base URL configuration
    this.baseUrl = import.meta.env?.PROD 
      ? 'https://security-api.security.svc.cluster.local'
      : 'http://localhost:3001';
    
    this.initializeApiKeys();
    this.initializeWebSocket();
  }

  /**
   * Initialize API keys safely for browser environment
   * Production: Use Vite environment variables or runtime config
   */
  private initializeApiKeys() {
    // Browser-safe environment variable access
    this.apiKeys = {
      gvm: import.meta.env?.VITE_GVM_API_KEY || ''
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
    gvm: GVMStatus;
  }>> {
    return this.makeRequest('/api/health/all');
  }

  /**
   * Check specific service health
   * Backend Endpoint: GET /api/health/{service}
   */
  async checkServiceHealth(service: 'gvm'): Promise<ApiResponse<ConnectionStatus>> {
    return this.makeRequest(`/api/health/${service}`);
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
    const services = ['gvm', 'zap'];
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
export const securityServicesApi = new SecurityServicesApiClient();

// Cleanup on page unload
if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', () => {
    securityServicesApi.cleanup();
  });
}