/**
 * Wazuh SIEM API Integration
 * Production-ready Wazuh API client with comprehensive error handling
 */

import { config, logger } from '@/config/environment';
import type { WazuhAgent, WazuhAlert, ConnectionStatus } from '@/types/security';

export interface MitreTechniqueMapping {
  techniqueId: string;
  techniqueName: string;
  tactics: string[];
  alertCount: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  lastSeen: string;
  relatedAlerts: string[];
}

export interface MitreTacticSummary {
  tacticName: string;
  tacticId: string;
  techniqueCount: number;
  totalAlerts: number;
  criticalTechniques: number;
}

interface WazuhApiResponse<T = any> {
  error: number;
  data: {
    affected_items: T[];
    total_affected_items: number;
    total_failed_items: number;
    failed_items: any[];
  };
  message: string;
}

class WazuhApiClient {
  private baseUrl: string;
  private credentials: { username: string; password: string };
  private token: string | null = null;
  private tokenExpiry: number = 0;

  constructor() {
    this.baseUrl = config.services.wazuh?.baseUrl || 'http://localhost:55000';
    this.credentials = {
      username: config.services.wazuh?.credentials?.username || 'wazuh',
      password: config.services.wazuh?.credentials?.password || 'wazuh'
    };
  }

  /**
   * Authenticate with Wazuh API and get JWT token
   */
  private async authenticate(): Promise<void> {
    try {
      const auth = btoa(`${this.credentials.username}:${this.credentials.password}`);
      const response = await fetch(`${this.baseUrl}/security/user/authenticate`, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Authentication failed: ${response.statusText}`);
      }

      const data = await response.json();
      this.token = data.data.token;
      this.tokenExpiry = Date.now() + (15 * 60 * 1000); // Token valid for 15 minutes
      logger.info('Wazuh authentication successful');
    } catch (error) {
      logger.error('Wazuh authentication failed', error);
      throw error;
    }
  }

  /**
   * Make authenticated request to Wazuh API
   */
  private async makeRequest<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<WazuhApiResponse<T>> {
    // Check if token needs refresh
    if (!this.token || Date.now() >= this.tokenExpiry) {
      await this.authenticate();
    }

    const url = `${this.baseUrl}${endpoint}`;
    const headers = {
      'Authorization': `Bearer ${this.token}`,
      'Content-Type': 'application/json',
      ...options.headers,
    };

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      if (!response.ok) {
        if (response.status === 401) {
          // Token expired, retry with new token
          await this.authenticate();
          return this.makeRequest<T>(endpoint, options);
        }
        throw new Error(`Request failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      logger.error('Wazuh API request failed', { endpoint, error });
      throw error;
    }
  }

  /**
   * Check Wazuh service health
   */
  async checkHealth(): Promise<ConnectionStatus> {
    try {
      const startTime = Date.now();
      const response = await this.makeRequest('/');
      const responseTime = Date.now() - startTime;

      return {
        online: true,
        lastCheck: new Date().toISOString(),
        error: null,
        responseTime,
        retryCount: 0,
        version: response.data as any,
      };
    } catch (error) {
      return {
        online: false,
        lastCheck: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error',
        responseTime: 0,
        retryCount: 0,
      };
    }
  }

  /**
   * Get all Wazuh agents
   */
  async getAgents(params?: {
    limit?: number;
    offset?: number;
    status?: string;
    search?: string;
  }): Promise<WazuhAgent[]> {
    try {
      const queryParams = new URLSearchParams();
      if (params?.limit) queryParams.append('limit', params.limit.toString());
      if (params?.offset) queryParams.append('offset', params.offset.toString());
      if (params?.status) queryParams.append('status', params.status);
      if (params?.search) queryParams.append('search', params.search);

      const endpoint = `/agents?${queryParams.toString()}`;
      const response = await this.makeRequest<any>(endpoint);

      return response.data.affected_items.map((agent: any) => ({
        id: agent.id,
        name: agent.name,
        ip: agent.ip,
        status: agent.status,
        os: {
          platform: agent.os?.platform || '',
          version: agent.os?.version || '',
          name: agent.os?.name || '',
        },
        version: agent.version || '',
        lastKeepAlive: agent.lastKeepAlive,
        nodeName: agent.node_name,
        dateAdd: agent.dateAdd,
        manager: agent.manager,
        group: agent.group,
      }));
    } catch (error) {
      logger.error('Failed to get Wazuh agents', error);
      throw error;
    }
  }

  /**
   * Get agent by ID
   */
  async getAgent(agentId: string): Promise<WazuhAgent> {
    try {
      const response = await this.makeRequest<any>(`/agents/${agentId}`);
      const agent = response.data.affected_items[0];

      return {
        id: agent.id,
        name: agent.name,
        ip: agent.ip,
        status: agent.status,
        os: {
          platform: agent.os?.platform || '',
          version: agent.os?.version || '',
          name: agent.os?.name || '',
        },
        version: agent.version || '',
        lastKeepAlive: agent.lastKeepAlive,
        nodeName: agent.node_name,
        dateAdd: agent.dateAdd,
        manager: agent.manager,
        group: agent.group,
      };
    } catch (error) {
      logger.error('Failed to get Wazuh agent', { agentId, error });
      throw error;
    }
  }

  /**
   * Get security alerts
   */
  async getAlerts(params?: {
    limit?: number;
    offset?: number;
    ruleLevel?: number;
    agentId?: string;
    timeRange?: string;
  }): Promise<WazuhAlert[]> {
    try {
      const queryParams = new URLSearchParams();
      if (params?.limit) queryParams.append('limit', params.limit.toString());
      if (params?.offset) queryParams.append('offset', params.offset.toString());
      if (params?.ruleLevel) queryParams.append('rule.level', `>=${params.ruleLevel}`);
      if (params?.agentId) queryParams.append('agent.id', params.agentId);

      const endpoint = `/security_events?${queryParams.toString()}`;
      const response = await this.makeRequest<any>(endpoint);

      return response.data.affected_items.map((alert: any) => ({
        id: alert.id || `${alert.agent?.id}-${alert.timestamp}`,
        timestamp: alert.timestamp,
        ruleId: alert.rule?.id || '',
        ruleLevel: alert.rule?.level || 0,
        ruleDescription: alert.rule?.description || '',
        agentId: alert.agent?.id || '',
        agentName: alert.agent?.name || '',
        location: alert.location || '',
        srcIp: alert.data?.srcip,
        dstIp: alert.data?.dstip,
        fullLog: alert.full_log || '',
        mitre: alert.rule?.mitre ? {
          id: alert.rule.mitre.id || [],
          tactic: alert.rule.mitre.tactic || [],
          technique: alert.rule.mitre.technique || [],
        } : undefined,
      }));
    } catch (error) {
      logger.error('Failed to get Wazuh alerts', error);
      throw error;
    }
  }

  /**
   * Restart agent
   */
  async restartAgent(agentId: string): Promise<void> {
    try {
      await this.makeRequest(`/agents/${agentId}/restart`, {
        method: 'PUT',
      });
      logger.info('Agent restarted successfully', { agentId });
    } catch (error) {
      logger.error('Failed to restart agent', { agentId, error });
      throw error;
    }
  }

  /**
   * Get agent statistics
   */
  async getAgentStats(): Promise<{
    total: number;
    active: number;
    disconnected: number;
    neverConnected: number;
    pending: number;
  }> {
    try {
      const agents = await this.getAgents({ limit: 1000 });
      
      return {
        total: agents.length,
        active: agents.filter(a => a.status === 'active').length,
        disconnected: agents.filter(a => a.status === 'disconnected').length,
        neverConnected: agents.filter(a => a.status === 'never_connected').length,
        pending: agents.filter(a => a.status === 'pending').length,
      };
    } catch (error) {
      logger.error('Failed to get agent statistics', error);
      return {
        total: 0,
        active: 0,
        disconnected: 0,
        neverConnected: 0,
        pending: 0,
      };
    }
  }

  /**
   * Get alert statistics
   */
  async getAlertStats(timeRange: string = '24h'): Promise<{
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }> {
    try {
      const alerts = await this.getAlerts({ limit: 1000, timeRange });
      
      return {
        total: alerts.length,
        critical: alerts.filter(a => a.ruleLevel >= 12).length,
        high: alerts.filter(a => a.ruleLevel >= 8 && a.ruleLevel < 12).length,
        medium: alerts.filter(a => a.ruleLevel >= 5 && a.ruleLevel < 8).length,
        low: alerts.filter(a => a.ruleLevel < 5).length,
      };
    } catch (error) {
      logger.error('Failed to get alert statistics', error);
      return {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      };
    }
  }

  /**
   * Get MITRE ATT&CK technique mappings from alerts
   */
  async getMitreTechniques(timeRange: string = '24h'): Promise<MitreTechniqueMapping[]> {
    try {
      const alerts = await this.getAlerts({ limit: 1000, timeRange });
      const techniqueMap = new Map<string, MitreTechniqueMapping>();

      alerts.forEach(alert => {
        if (alert.mitre?.id) {
          alert.mitre.id.forEach((techId, idx) => {
            const techName = alert.mitre?.technique[idx] || 'Unknown';
            const tactics = alert.mitre?.tactic || [];

            if (techniqueMap.has(techId)) {
              const existing = techniqueMap.get(techId)!;
              existing.alertCount++;
              existing.relatedAlerts.push(alert.id);
              existing.lastSeen = alert.timestamp > existing.lastSeen ? alert.timestamp : existing.lastSeen;
            } else {
              const severity = alert.ruleLevel >= 12 ? 'critical' : 
                             alert.ruleLevel >= 8 ? 'high' :
                             alert.ruleLevel >= 5 ? 'medium' : 'low';
              
              techniqueMap.set(techId, {
                techniqueId: techId,
                techniqueName: techName,
                tactics: tactics,
                alertCount: 1,
                severity,
                lastSeen: alert.timestamp,
                relatedAlerts: [alert.id]
              });
            }
          });
        }
      });

      return Array.from(techniqueMap.values());
    } catch (error) {
      logger.error('Failed to get MITRE techniques', error);
      return [];
    }
  }

  /**
   * Get MITRE ATT&CK tactic summary
   */
  async getMitreTactics(timeRange: string = '24h'): Promise<MitreTacticSummary[]> {
    try {
      const techniques = await this.getMitreTechniques(timeRange);
      const tacticMap = new Map<string, MitreTacticSummary>();

      techniques.forEach(tech => {
        tech.tactics.forEach(tactic => {
          if (tacticMap.has(tactic)) {
            const existing = tacticMap.get(tactic)!;
            existing.techniqueCount++;
            existing.totalAlerts += tech.alertCount;
            if (tech.severity === 'critical') {
              existing.criticalTechniques++;
            }
          } else {
            tacticMap.set(tactic, {
              tacticName: tactic,
              tacticId: '',
              techniqueCount: 1,
              totalAlerts: tech.alertCount,
              criticalTechniques: tech.severity === 'critical' ? 1 : 0
            });
          }
        });
      });

      return Array.from(tacticMap.values());
    } catch (error) {
      logger.error('Failed to get MITRE tactics', error);
      return [];
    }
  }

  /**
   * Get detailed alerts for a specific MITRE technique
   */
  async getMitreTechniqueAlerts(techniqueId: string): Promise<WazuhAlert[]> {
    try {
      const alerts = await this.getAlerts({ limit: 1000 });
      return alerts.filter(alert => 
        alert.mitre?.id.includes(techniqueId)
      );
    } catch (error) {
      logger.error('Failed to get MITRE technique alerts', { techniqueId, error });
      return [];
    }
  }
}

export const wazuhApi = new WazuhApiClient();
export default wazuhApi;
