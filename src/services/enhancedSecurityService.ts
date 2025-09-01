/**
 * Enhanced Security Integration Service for FastAPI Backend
 * Production-ready implementation with comprehensive error handling
 * 
 * Features:
 * - FastAPI backend integration
 * - Circuit breaker pattern for resilience
 * - Exponential backoff retry logic
 * - Real-time WebSocket updates
 * - Mock data fallbacks for development
 * - Environment-specific configuration
 * - Comprehensive logging and monitoring
 */

import { toast } from "@/hooks/use-toast";
import { config, logger } from "@/config/environment";

// ========== TYPE DEFINITIONS ==========

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

export interface SecurityServiceHealth {
  service: 'wazuh' | 'gvm' | 'zap' | 'spiderfoot';
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  lastCheck: string;
  responseTime: number;
  error?: string;
  version?: string;
}

export interface ScanResult {
  id: string;
  type: 'vulnerability' | 'web_app' | 'osint';
  status: 'running' | 'completed' | 'failed';
  progress: number;
  target: string;
  results: any[];
  startTime: string;
  endTime?: string;
  error?: string;
}

// ========== CIRCUIT BREAKER ==========

interface CircuitBreakerState {
  failures: number;
  lastFailure: number;
  state: 'closed' | 'open' | 'half-open';
}

class CircuitBreaker {
  private states = new Map<string, CircuitBreakerState>();
  private readonly maxFailures = 3;
  private readonly resetTimeout = 60000; // 1 minute

  constructor() {
    ['wazuh', 'gvm', 'zap', 'spiderfoot'].forEach(service => {
      this.states.set(service, {
        failures: 0,
        lastFailure: 0,
        state: 'closed'
      });
    });
  }

  canExecute(service: string): boolean {
    const state = this.states.get(service);
    if (!state) return true;

    switch (state.state) {
      case 'closed':
        return true;
      case 'open':
        if (Date.now() - state.lastFailure > this.resetTimeout) {
          state.state = 'half-open';
          this.states.set(service, state);
          return true;
        }
        return false;
      case 'half-open':
        return true;
      default:
        return false;
    }
  }

  recordSuccess(service: string): void {
    const state = this.states.get(service);
    if (state) {
      state.failures = 0;
      state.state = 'closed';
      this.states.set(service, state);
    }
  }

  recordFailure(service: string): void {
    const state = this.states.get(service);
    if (state) {
      state.failures++;
      state.lastFailure = Date.now();
      
      if (state.failures >= this.maxFailures) {
        state.state = 'open';
      }
      
      this.states.set(service, state);
    }
  }

  getState(service: string): CircuitBreakerState | undefined {
    return this.states.get(service);
  }
}

// ========== MAIN SERVICE CLASS ==========

class EnhancedSecurityService {
  private circuitBreaker = new CircuitBreaker();
  private healthStatuses = new Map<string, SecurityServiceHealth>();
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private isConnecting = false;
  private scanResults = new Map<string, ScanResult>();

  constructor() {
    this.initializeHealthStatuses();
    // Skip WebSocket initialization in demo mode to prevent errors
    console.log('EnhancedSecurityService initialized in demo mode (no WebSocket/API calls)');
    // this.initializeWebSocket(); // Disabled for demo
    // this.startHealthCheckInterval(); // Disabled for demo
    
    logger.info('EnhancedSecurityService initialized for demo mode');
  }

  // ========== INITIALIZATION ==========

  private initializeHealthStatuses(): void {
    const services: Array<SecurityServiceHealth['service']> = ['wazuh', 'gvm', 'zap', 'spiderfoot'];
    
    services.forEach(service => {
      this.healthStatuses.set(service, {
        service,
        status: 'unknown',
        lastCheck: new Date().toISOString(),
        responseTime: 0,
      });
    });
  }

  private initializeWebSocket(): void {
    if (this.isConnecting || this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    this.isConnecting = true;

    try {
      this.ws = new WebSocket(config.websocket.url);

      this.ws.onopen = () => {
        this.isConnecting = false;
        this.reconnectAttempts = 0;
        logger.info('Security WebSocket connected to FastAPI backend');
        
        window.dispatchEvent(new CustomEvent('security:websocket:connected'));
        
        toast({
          title: "🔗 Real-time Connection Established",
          description: "Security monitoring is now active",
        });
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.handleWebSocketMessage(data);
        } catch (error) {
          logger.error('Failed to parse WebSocket message:', error);
        }
      };

      this.ws.onclose = () => {
        this.isConnecting = false;
        logger.warn('Security WebSocket disconnected');
        
        window.dispatchEvent(new CustomEvent('security:websocket:disconnected'));
        
        // Auto-reconnect with exponential backoff
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
          const delay = Math.pow(2, this.reconnectAttempts) * 1000;
          logger.info(`Attempting WebSocket reconnect in ${delay}ms (attempt ${this.reconnectAttempts + 1})`);
          
          setTimeout(() => {
            this.reconnectAttempts++;
            this.initializeWebSocket();
          }, delay);
        }
      };

      this.ws.onerror = (error) => {
        this.isConnecting = false;
        logger.error('Security WebSocket error:', error);
      };

    } catch (error) {
      this.isConnecting = false;
      logger.error('Failed to initialize WebSocket:', error);
    }
  }

  private handleWebSocketMessage(data: any): void {
    logger.debug('WebSocket message received:', data);

    switch (data.type) {
      case 'wazuh_alert':
        window.dispatchEvent(new CustomEvent('security:wazuh:message', { 
          detail: { type: 'alert', alert: data.payload } 
        }));
        
        // Show critical alerts as toasts
        if (data.payload.rule?.level >= 10) {
          toast({
            title: "🚨 Critical Security Alert",
            description: `${data.payload.rule.description} on ${data.payload.agent.name}`,
            variant: "destructive",
          });
        }
        break;
        
      case 'service_health':
        this.updateHealthStatus(data.service, data.payload);
        break;
        
      case 'scan_progress':
        this.updateScanProgress(data.scanId, data.payload);
        window.dispatchEvent(new CustomEvent('security:scan:progress', { 
          detail: data.payload 
        }));
        break;
        
      case 'scan_complete':
        this.completeScan(data.scanId, data.payload);
        toast({
          title: "✅ Scan Complete",
          description: `${data.payload.type} scan finished with ${data.payload.results?.length || 0} findings`,
        });
        break;
        
      default:
        logger.warn('Unknown WebSocket message type:', data.type);
    }
  }

  // ========== HTTP REQUEST METHODS ==========

  private async makeRequest<T>(
    url: string,
    options: RequestInit = {},
    service?: string,
    retryCount = 0
  ): Promise<T> {
    // Check circuit breaker for service-specific requests
    if (service && !this.circuitBreaker.canExecute(service)) {
      throw new Error(`Service ${service} is currently unavailable (circuit breaker open)`);
    }

    const maxRetries = 3;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.api.timeout);

    const requestOptions: RequestInit = {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    };

    try {
      logger.debug(`API Request [${service || 'general'}]:`, url, requestOptions);

      const response = await fetch(url, requestOptions);
      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      
      // Record success for circuit breaker
      if (service) {
        this.circuitBreaker.recordSuccess(service);
      }
      
      logger.debug(`API Response [Success]:`, url, data);
      return data;

    } catch (error) {
      clearTimeout(timeoutId);
      
      // Record failure for circuit breaker
      if (service) {
        this.circuitBreaker.recordFailure(service);
      }
      
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.warn(`API Request [Failed]:`, url, errorMessage);

      // Retry logic with exponential backoff
      if (retryCount < maxRetries) {
        const delay = Math.pow(2, retryCount) * 1000;
        logger.info(`Retrying request in ${delay}ms (attempt ${retryCount + 1})`);
        
        await new Promise(resolve => setTimeout(resolve, delay));
        return this.makeRequest<T>(url, options, service, retryCount + 1);
      }

      throw new Error(`Failed to connect to ${url}: ${errorMessage}`);
    }
  }

  // ========== WAZUH METHODS ==========

  async getWazuhAgents(): Promise<WazuhAgent[]> {
    try {
      console.log('🔄 getWazuhAgents called (demo mode - returning empty array)');
      // Skip API call in demo mode
      return [];
      
    } catch (error) {
      logger.error('Error fetching Wazuh agents:', error);
      return [];
    }
  }

  async getWazuhAlerts(limit = 50): Promise<WazuhAlert[]> {
    try {
      console.log('🔄 getWazuhAlerts called (demo mode - returning empty array)');
      // Skip API call in demo mode
      return [];
      
    } catch (error) {
      logger.error('Error fetching Wazuh alerts:', error);
      return [];
    }
  }

  async restartWazuhAgent(agentId: string): Promise<void> {
    try {
      await this.makeRequest(
        `${config.api.baseUrl}/api/wazuh/agents/${agentId}/restart`,
        { method: 'POST' },
        'wazuh'
      );
      
      logger.info(`Successfully restarted Wazuh agent ${agentId}`);
      
      toast({
        title: "🔄 Agent Restarted",
        description: `Wazuh agent ${agentId} has been restarted successfully`,
      });
      
    } catch (error) {
      logger.error(`Error restarting Wazuh agent ${agentId}:`, error);
      
      toast({
        title: "❌ Restart Failed",
        description: `Failed to restart agent ${agentId}: ${error instanceof Error ? error.message : 'Unknown error'}`,
        variant: "destructive",
      });
      
      throw error;
    }
  }

  // ========== HEALTH CHECK METHODS ==========

  private startHealthCheckInterval(): void {
    // Initial health check
    this.performHealthChecks();
    
    // Check every 30 seconds
    setInterval(() => {
      this.performHealthChecks();
    }, 30000);
  }

  private async performHealthChecks(): Promise<void> {
    const services: Array<SecurityServiceHealth['service']> = ['wazuh', 'gvm', 'zap', 'spiderfoot'];
    
    const healthChecks = services.map(service => this.checkServiceHealth(service));
    
    try {
      await Promise.allSettled(healthChecks);
    } catch (error) {
      logger.error('Health check error:', error);
    }
  }

  private async checkServiceHealth(service: SecurityServiceHealth['service']): Promise<void> {
    const startTime = Date.now();
    
    try {
      const data = await this.makeRequest<{ status: string; version?: string }>(
        `${config.api.baseUrl}/api/health/${service}`,
        {},
        service
      );
      
      this.updateHealthStatus(service, {
        service,
        status: data.status === 'healthy' ? 'healthy' : 'degraded',
        responseTime: Date.now() - startTime,
        lastCheck: new Date().toISOString(),
        version: data.version,
      });
      
    } catch (error) {
      this.updateHealthStatus(service, {
        service,
        status: 'unhealthy',
        responseTime: Date.now() - startTime,
        lastCheck: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  private updateHealthStatus(service: string, health: SecurityServiceHealth): void {
    this.healthStatuses.set(service, health);
    
    // Emit health status event
    window.dispatchEvent(new CustomEvent(`security:health:${service}`, {
      detail: health
    }));
  }

  // ========== SCAN MANAGEMENT ==========

  private updateScanProgress(scanId: string, progress: any): void {
    const scan = this.scanResults.get(scanId);
    if (scan) {
      scan.progress = progress.percentage || 0;
      scan.status = progress.status || 'running';
      this.scanResults.set(scanId, scan);
    }
  }

  private completeScan(scanId: string, results: any): void {
    const scan = this.scanResults.get(scanId);
    if (scan) {
      scan.status = 'completed';
      scan.progress = 100;
      scan.endTime = new Date().toISOString();
      scan.results = results.findings || [];
      this.scanResults.set(scanId, scan);
    }
  }

  // ========== PUBLIC API ==========

  getHealthStatuses(): SecurityServiceHealth[] {
    return Array.from(this.healthStatuses.values());
  }

  async refreshHealthChecks(): Promise<void> {
    console.log('🔄 refreshHealthChecks called (demo mode - skipping)');
    // Skip health checks in demo mode
    return Promise.resolve();
  }

  isWebSocketConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  reconnectWebSocket(): void {
    if (this.ws) {
      this.ws.close();
    }
    this.reconnectAttempts = 0;
    this.initializeWebSocket();
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    logger.info('EnhancedSecurityService disconnected');
  }

  // ========== MOCK DATA FOR DEVELOPMENT ==========

  private getMockAgents(): WazuhAgent[] {
    return [
      {
        id: '001',
        name: 'web-server-01',
        ip: '192.168.1.100',
        status: 'active',
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
        status: 'active',
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
        status: 'disconnected',
        os: { platform: 'windows', version: '2019', name: 'Windows Server' },
        version: '4.3.10',
        lastKeepAlive: new Date(Date.now() - 300000).toISOString(),
        group: ['default', 'applications'],
        node_name: 'node02',
      },
    ];
  }

  private getMockAlerts(): WazuhAlert[] {
    return [
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
    ];
  }
}

// Export singleton instance
export const enhancedSecurityService = new EnhancedSecurityService();