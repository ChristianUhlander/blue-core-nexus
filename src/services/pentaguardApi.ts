/**
 * Pentaguard API Service
 * Integration with the Pentaguard backend API
 * Based on OpenAPI specification provided
 */

// API Types based on OpenAPI spec
export interface TargetOut {
  id: number;
  name: string;
  hosts: string[];
  comment: string;
  gvmid: string;
  port_list_id: string;
  is_active: boolean;
}

export interface TargetIn {
  name: string;
  hosts: string[];
  comment: string;
  gvmid: string;
  port_list_id: string;
  is_active: boolean;
}

export interface ReportOut {
  id: number | null;
  report_name: string;
  target_name: string;
  report_id: string;
  target_id: string;
  task_id: string;
  scan_start: string;
  scan_end: string;
  file_name: string;
}

export interface ScannerOut {
  id: string;
  name: string;
  host: string;
  port: string;
  scanner_type: string;
  status: string;
}

export interface ChatbotRequest {
  message: string;
  model?: string;
}

export interface TaskIn {
  name: string;
  config_id: string;
  target_id: string;
  scanner_id: string;
  alterable?: boolean;
  schedule_periods?: number;
  schedule_id: string;
  comment: string;
}

export interface ReportRequest {
  scanData: string;
  reportType: string;
}

export interface ReportResponse {
  report: string;
}

export interface ZapScanRequest {
  target: string;
}

export interface ReconScanRequest {
  modules: string[];
  target: string;
  workspace?: string;
  export_csv?: string;
}

export interface SpiderScanRequest {
  target: string;
}

export interface WazuhLogRequest {
  filename?: string;
  date?: string;
  format?: string;
}

class PentaguardApiService {
  private baseUrl: string;
  private wsConnection: WebSocket | null = null;

  constructor() {
    this.baseUrl = import.meta.env?.PROD
      ? 'https://pentaguard:3001'
      : 'http://localhost:3001';
    
    this.initializeWebSocket();
  }

  private initializeWebSocket() {
    const wsUrl = `ws://pentaguard:3001/ws`;
    
    try {
      this.wsConnection = new WebSocket(wsUrl);
      
      this.wsConnection.onopen = () => {
        console.log('🔗 Pentaguard WebSocket connected');
      };
      
      this.wsConnection.onmessage = (event) => {
        const message = JSON.parse(event.data);
        this.handleWebSocketMessage(message);
      };
      
      this.wsConnection.onclose = () => {
        console.log('🔗 Pentaguard WebSocket disconnected');
        this.scheduleReconnect();
      };
      
    } catch (error) {
      console.error('❌ Failed to initialize Pentaguard WebSocket:', error);
    }
  }

  private handleWebSocketMessage(message: any) {
    // Dispatch custom event for UI updates
    const event = new CustomEvent('pentaguard:message', {
      detail: message
    });
    window.dispatchEvent(event);
  }

  private scheduleReconnect() {
    setTimeout(() => {
      console.log('🔄 Attempting Pentaguard WebSocket reconnection...');
      this.initializeWebSocket();
    }, 5000);
  }

  private async makeRequest<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error(`API request failed for ${endpoint}:`, error);
      throw error;
    }
  }

  // Target Management
  async getTargets(limit = 100): Promise<TargetOut[]> {
    return this.makeRequest(`/api/v1/targets/?limit=${limit}`);
  }

  async createOrUpdateTarget(target: TargetIn): Promise<any> {
    return this.makeRequest('/api/v1/targets/create_or_update', {
      method: 'POST',
      body: JSON.stringify(target)
    });
  }

  async deleteTarget(id: number): Promise<any> {
    return this.makeRequest('/api/v1/targets/delete', {
      method: 'POST',
      body: JSON.stringify({ id })
    });
  }

  // GVM Management
  async getGvmStatus(): Promise<any> {
    return this.makeRequest('/api/v1/gvm/status');
  }

  async getPortLists(limit = 50): Promise<any[]> {
    return this.makeRequest(`/api/v1/gvm/port_lists?limit=${limit}`);
  }

  async getScanners(): Promise<ScannerOut[]> {
    return this.makeRequest('/api/v1/gvm/scanners');
  }

  async getScanConfigs(): Promise<any> {
    return this.makeRequest('/api/v1/gvm/scan_configs');
  }

  async createTask(task: TaskIn): Promise<any> {
    return this.makeRequest('/api/v1/gvm/task/create', {
      method: 'POST',
      body: JSON.stringify(task)
    });
  }

  async startScan(target: { name: string }): Promise<any> {
    return this.makeRequest('/api/v1/gvm/scan/start', {
      method: 'POST',
      body: JSON.stringify(target)
    });
  }

  async getReports(): Promise<ReportOut[]> {
    return this.makeRequest('/api/v1/gvm/reports');
  }

  async getSchedules(): Promise<any> {
    return this.makeRequest('/api/v1/gvm/schedules');
  }

  async downloadReport(reportId: string, format: string): Promise<any> {
    return this.makeRequest('/api/v1/gvm/reports/download', {
      method: 'POST',
      body: JSON.stringify({ report_id: reportId, format })
    });
  }

  // ZAP Scanning
  async startZapScan(request: ZapScanRequest): Promise<any> {
    return this.makeRequest('/api/v1/zap/scan', {
      method: 'POST',
      body: JSON.stringify(request)
    });
  }

  async getZapReports(): Promise<any> {
    return this.makeRequest('/api/v1/zap/reports');
  }

  async downloadZapReport(reportId: string, format: string): Promise<any> {
    return this.makeRequest('/api/v1/zap/reports/download', {
      method: 'POST',
      body: JSON.stringify({ report_id: reportId, format })
    });
  }

  // Wazuh Management
  async getWazuhLogs(): Promise<any> {
    return this.makeRequest('/api/v1/wazuh/logs');
  }

  async getWazuhStatus(): Promise<any> {
    return this.makeRequest('/api/v1/wazuh/status');
  }

  async downloadWazuhLog(request: WazuhLogRequest): Promise<any> {
    return this.makeRequest('/api/v1/wazuh/logs/download', {
      method: 'POST',
      body: JSON.stringify(request)
    });
  }

  // Chatbot
  async chatbotHttp(request: ChatbotRequest): Promise<any> {
    return this.makeRequest('/api/v1/chatbot/http', {
      method: 'POST',
      body: JSON.stringify(request)
    });
  }

  // Recon-ng
  async scheduleReconScan(request: ReconScanRequest): Promise<any> {
    return this.makeRequest('/api/v1/recon/api/v1/recon/scan', {
      method: 'POST',
      body: JSON.stringify(request)
    });
  }

  // SpiderFoot
  async launchSpiderfoot(request: SpiderScanRequest): Promise<any> {
    return this.makeRequest('/api/v1/spiderfoot/api/v1/spiderfoot/scan', {
      method: 'POST',
      body: JSON.stringify(request)
    });
  }

  // AI Report Generation
  async generateReport(request: ReportRequest): Promise<ReportResponse> {
    return this.makeRequest('/api/v1/report/generate', {
      method: 'POST',
      body: JSON.stringify(request)
    });
  }

  // Health Checks
  async healthCheck(): Promise<any> {
    return this.makeRequest('/healthz');
  }

  async readinessCheck(): Promise<any> {
    return this.makeRequest('/readyz');
  }

  async livenessCheck(): Promise<any> {
    return this.makeRequest('/livez');
  }

  // WebSocket Info
  async getWebSocketInfo(): Promise<any> {
    return this.makeRequest('/ws-info');
  }
}

export const pentaguardApi = new PentaguardApiService();