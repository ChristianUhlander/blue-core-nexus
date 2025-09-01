# Wazuh SBOM API Reference

## Overview

This document provides detailed API reference for the Wazuh SBOM (Software Bill of Materials) integration system. The APIs enable programmatic access to software inventory data, vulnerability information, and SBOM generation capabilities.

## Base Configuration

### API Endpoints

```typescript
const WAZUH_BASE_URL = process.env.WAZUH_API_URL || 'https://wazuh-manager:55000';
const API_VERSION = 'v1';
const BASE_PATH = `/api/${API_VERSION}`;
```

### Authentication

All API calls require JWT authentication:

```typescript
// Authentication flow
const authResponse = await fetch(`${WAZUH_BASE_URL}/security/user/authenticate`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Basic ${btoa(`${username}:${password}`)}`
  }
});

const { token } = await authResponse.json();

// Use token in subsequent requests
const headers = {
  'Authorization': `Bearer ${token}`,
  'Content-Type': 'application/json'
};
```

## Core API Endpoints

### 1. Agent Management

#### List All Agents
```typescript
GET /agents
```

**Query Parameters:**
- `limit`: Number of results to return (default: 500)
- `offset`: Starting position for pagination
- `search`: Text search across agent fields
- `q`: WQL (Wazuh Query Language) filter

**Response:**
```json
{
  "data": {
    "affected_items": [
      {
        "id": "001",
        "name": "web-server-01",
        "ip": "192.168.1.10",
        "status": "active",
        "os": {
          "name": "Ubuntu",
          "version": "20.04",
          "platform": "ubuntu"
        },
        "version": "4.12.0",
        "lastKeepAlive": "2024-01-15T10:30:00Z"
      }
    ],
    "total_affected_items": 1
  }
}
```

#### Get Specific Agent
```typescript
GET /agents/{agent_id}
```

**Path Parameters:**
- `agent_id`: Agent identifier (e.g., "001")

### 2. System Inventory (Syscollector)

#### Get Agent Packages
```typescript
GET /experimental/syscollector/{agent_id}/packages
```

**Query Parameters:**
- `limit`: Number of packages to return
- `offset`: Pagination offset
- `search`: Package name search
- `select`: Fields to include in response
- `sort`: Sort order

**Response:**
```json
{
  "data": {
    "affected_items": [
      {
        "scan_time": "2024-01-15T10:30:00Z",
        "name": "openssl",
        "version": "1.1.1f-1ubuntu2.19",
        "architecture": "amd64",
        "format": "deb",
        "vendor": "Ubuntu Developers",
        "description": "Secure Sockets Layer toolkit - cryptographic utility",
        "size": 1234567,
        "install_time": "2023-06-15T14:20:00Z",
        "location": "/usr/bin/openssl"
      }
    ],
    "total_affected_items": 150
  }
}
```

#### Get Agent Hardware
```typescript
GET /experimental/syscollector/{agent_id}/hardware
```

**Response:**
```json
{
  "data": {
    "affected_items": [
      {
        "scan_time": "2024-01-15T10:30:00Z",
        "board_serial": "BSN123456789",
        "cpu_name": "Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz",
        "cpu_cores": 8,
        "cpu_mhz": 3700.0,
        "ram_total": 16777216,
        "ram_free": 8388608
      }
    ]
  }
}
```

#### Get Agent Operating System
```typescript
GET /experimental/syscollector/{agent_id}/os
```

**Response:**
```json
{
  "data": {
    "affected_items": [
      {
        "scan_time": "2024-01-15T10:30:00Z",
        "hostname": "web-server-01",
        "architecture": "x86_64",
        "os_name": "Ubuntu",
        "os_version": "20.04.6 LTS",
        "os_codename": "focal",
        "os_major": "20",
        "os_minor": "04",
        "os_patch": "6",
        "os_build": "focal",
        "os_platform": "ubuntu",
        "sysname": "Linux",
        "release": "5.4.0-169-generic",
        "version": "#187-Ubuntu SMP Thu Nov 23 14:52:28 UTC 2023"
      }
    ]
  }
}
```

### 3. Vulnerability Detection

#### Get Vulnerabilities
```typescript
GET /vulnerability
```

**Query Parameters:**
- `q`: WQL filter (e.g., `agent_id=001;severity=high`)
- `limit`: Number of results
- `offset`: Pagination offset
- `sort`: Sort order

**Response:**
```json
{
  "data": {
    "affected_items": [
      {
        "agent_id": "001",
        "agent_name": "web-server-01",
        "cve": "CVE-2023-0286",
        "title": "X.400 address type confusion in X.509 GeneralName",
        "severity": "High",
        "cvss2_score": 7.4,
        "cvss3_score": 7.4,
        "published": "2023-02-07T00:00:00Z",
        "updated": "2023-02-08T00:00:00Z",
        "package_name": "openssl",
        "package_version": "1.1.1f-1ubuntu2.19",
        "condition": "Package less than 1.1.1t",
        "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0286"]
      }
    ],
    "total_affected_items": 5
  }
}
```

## SBOM Generation Service

### Core SBOM Service Implementation

```typescript
export class WazuhSBOMService {
  private apiClient: WazuhAPIClient;
  private baseUrl: string;

  constructor(baseUrl: string, credentials: WazuhCredentials) {
    this.baseUrl = baseUrl;
    this.apiClient = new WazuhAPIClient(baseUrl, credentials);
  }

  /**
   * Generate comprehensive SBOM for an agent
   */
  async generateSBOM(
    agentId: string, 
    options: SBOMGenerationOptions = {}
  ): Promise<SBOMData> {
    const {
      format = 'cyclonedx',
      includeVulnerabilities = true,
      includeHardware = false,
      includeProcesses = false
    } = options;

    try {
      // 1. Fetch agent information
      const agent = await this.getAgent(agentId);
      
      // 2. Collect system inventory
      const [packages, osInfo, hardware] = await Promise.all([
        this.getAgentPackages(agentId),
        this.getAgentOS(agentId),
        includeHardware ? this.getAgentHardware(agentId) : null
      ]);

      // 3. Correlate vulnerabilities if requested
      const vulnerabilities = includeVulnerabilities 
        ? await this.getAgentVulnerabilities(agentId)
        : [];

      // 4. Generate SBOM based on format
      return this.formatSBOM({
        agent,
        packages,
        osInfo,
        hardware,
        vulnerabilities,
        format
      });

    } catch (error) {
      throw new SBOMGenerationError(`Failed to generate SBOM for agent ${agentId}: ${error.message}`);
    }
  }

  /**
   * Get agent basic information
   */
  private async getAgent(agentId: string): Promise<WazuhAgent> {
    const response = await this.apiClient.get(`/agents/${agentId}`);
    return response.data.affected_items[0];
  }

  /**
   * Get agent package inventory
   */
  private async getAgentPackages(agentId: string): Promise<SoftwarePackage[]> {
    const packages: SoftwarePackage[] = [];
    let offset = 0;
    const limit = 500;

    do {
      const response = await this.apiClient.get(
        `/experimental/syscollector/${agentId}/packages`,
        { params: { limit, offset, select: 'name,version,architecture,format,vendor,description,size,install_time' } }
      );

      const items = response.data.affected_items;
      packages.push(...items.map(this.mapPackageData));
      
      offset += limit;
      
      // Break if we got fewer items than requested (last page)
      if (items.length < limit) break;
      
    } while (true);

    return packages;
  }

  /**
   * Get agent vulnerabilities
   */
  private async getAgentVulnerabilities(agentId: string): Promise<VulnerabilityInfo[]> {
    const response = await this.apiClient.get('/vulnerability', {
      params: {
        q: `agent_id=${agentId}`,
        limit: 1000,
        sort: '-cvss3_score'
      }
    });

    return response.data.affected_items.map(this.mapVulnerabilityData);
  }

  /**
   * Format SBOM based on requested format
   */
  private formatSBOM(data: SBOMFormatData): SBOMData {
    const { agent, packages, osInfo, hardware, vulnerabilities, format } = data;

    const sbom: SBOMData = {
      id: `sbom-${agent.id}-${Date.now()}`,
      agent_id: agent.id,
      agent_name: agent.name,
      generated_at: new Date().toISOString(),
      format,
      packages,
      vulnerabilities,
      metadata: {
        os: osInfo.os_name + ' ' + osInfo.os_version,
        architecture: osInfo.architecture,
        scan_time: new Date().toISOString(),
        total_packages: packages.length,
        vulnerable_packages: vulnerabilities.length,
        ...(hardware && { hardware })
      }
    };

    return sbom;
  }

  /**
   * Export SBOM in specified format
   */
  async exportSBOM(sbom: SBOMData, format: 'json' | 'xml' | 'csv'): Promise<string> {
    switch (format) {
      case 'json':
        return this.exportAsJSON(sbom);
      case 'xml':
        return this.exportAsCycloneDX(sbom);
      case 'csv':
        return this.exportAsCSV(sbom);
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  /**
   * Export as JSON
   */
  private exportAsJSON(sbom: SBOMData): string {
    return JSON.stringify(sbom, null, 2);
  }

  /**
   * Export as CycloneDX XML
   */
  private exportAsCycloneDX(sbom: SBOMData): string {
    const components = sbom.packages.map(pkg => `
    <component type="library" bom-ref="${pkg.id}">
      <name>${this.escapeXml(pkg.name)}</name>
      <version>${this.escapeXml(pkg.version)}</version>
      <description>${this.escapeXml(pkg.description || '')}</description>
      <licenses>
        <license>
          <name>Unknown</name>
        </license>
      </licenses>
      <properties>
        <property name="vendor">${this.escapeXml(pkg.vendor || '')}</property>
        <property name="architecture">${this.escapeXml(pkg.architecture)}</property>
        <property name="format">${this.escapeXml(pkg.format || '')}</property>
        <property name="size">${pkg.size || 0}</property>
      </properties>
    </component>`).join('');

    const vulnerabilities = sbom.vulnerabilities.map(vuln => `
    <vulnerability bom-ref="${vuln.cve}">
      <id>${vuln.cve}</id>
      <source>
        <name>Wazuh Vulnerability Detection</name>
      </source>
      <ratings>
        <rating>
          <source>
            <name>CVSS v3.1</name>
          </source>
          <score>${vuln.score}</score>
          <severity>${vuln.severity.toUpperCase()}</severity>
        </rating>
      </ratings>
      <description>${this.escapeXml(vuln.description)}</description>
      <published>${vuln.published}</published>
      <affects>
        <target>
          <ref>${sbom.packages.find(p => p.name === vuln.affected_package)?.id || vuln.affected_package}</ref>
        </target>
      </affects>
    </vulnerability>`).join('');

    return `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" serialNumber="urn:uuid:${this.generateUUID()}" version="1">
  <metadata>
    <timestamp>${sbom.generated_at}</timestamp>
    <tools>
      <tool>
        <vendor>Wazuh</vendor>
        <name>SBOM Generator</name>
        <version>1.0.0</version>
      </tool>
    </tools>
    <component type="operating-system" bom-ref="${sbom.agent_id}">
      <name>${this.escapeXml(sbom.agent_name)}</name>
      <description>System: ${this.escapeXml(sbom.metadata.os)}</description>
      <properties>
        <property name="architecture">${this.escapeXml(sbom.metadata.architecture)}</property>
      </properties>
    </component>
  </metadata>
  <components>${components}
  </components>
  <vulnerabilities>${vulnerabilities}
  </vulnerabilities>
</bom>`;
  }

  /**
   * Export as CSV
   */
  private exportAsCSV(sbom: SBOMData): string {
    const headers = [
      'Package Name',
      'Version', 
      'Vendor',
      'Architecture',
      'Format',
      'Description',
      'Install Time',
      'Size (KB)',
      'CVEs',
      'Max CVSS Score',
      'Risk Level'
    ];

    const rows = sbom.packages.map(pkg => {
      const relatedVulns = sbom.vulnerabilities.filter(v => v.affected_package === pkg.name);
      const maxScore = relatedVulns.length > 0 ? Math.max(...relatedVulns.map(v => v.score)) : 0;
      const riskLevel = maxScore >= 9 ? 'Critical' : maxScore >= 7 ? 'High' : maxScore >= 4 ? 'Medium' : 'Low';

      return [
        `"${pkg.name}"`,
        `"${pkg.version}"`,
        `"${pkg.vendor || ''}"`,
        `"${pkg.architecture}"`,
        `"${pkg.format || ''}"`,
        `"${(pkg.description || '').replace(/"/g, '""')}"`,
        `"${pkg.install_time || ''}"`,
        `"${pkg.size ? Math.round(pkg.size / 1024) : ''}"`,
        `"${relatedVulns.map(v => v.cve).join(';')}"`,
        `"${maxScore}"`,
        `"${riskLevel}"`
      ].join(',');
    });

    return [headers.join(','), ...rows].join('\n');
  }

  // Utility methods
  private mapPackageData(rawPackage: any): SoftwarePackage {
    return {
      id: `pkg-${rawPackage.name}-${rawPackage.version}`,
      name: rawPackage.name,
      version: rawPackage.version,
      vendor: rawPackage.vendor,
      architecture: rawPackage.architecture,
      description: rawPackage.description,
      install_time: rawPackage.install_time,
      size: rawPackage.size,
      format: rawPackage.format as any
    };
  }

  private mapVulnerabilityData(rawVuln: any): VulnerabilityInfo {
    return {
      cve: rawVuln.cve,
      severity: rawVuln.severity.toLowerCase() as any,
      score: rawVuln.cvss3_score || rawVuln.cvss2_score || 0,
      description: rawVuln.title,
      published: rawVuln.published,
      references: rawVuln.references || [],
      affected_package: rawVuln.package_name,
      fixed_version: rawVuln.condition?.match(/less than (\S+)/)?.[1]
    };
  }

  private escapeXml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }

  private generateUUID(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c == 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}
```

## Error Handling

### Custom Error Classes

```typescript
export class SBOMGenerationError extends Error {
  constructor(message: string, public cause?: Error) {
    super(message);
    this.name = 'SBOMGenerationError';
  }
}

export class WazuhAPIError extends Error {
  constructor(message: string, public statusCode?: number, public response?: any) {
    super(message);
    this.name = 'WazuhAPIError';
  }
}
```

### Error Response Format

```json
{
  "error": true,
  "message": "Failed to generate SBOM",
  "details": {
    "agent_id": "001",
    "error_code": "SYSCOLLECTOR_UNAVAILABLE",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

## Rate Limiting and Performance

### API Rate Limits

```typescript
// Rate limiting configuration
const RATE_LIMITS = {
  per_minute: 100,
  per_hour: 1000,
  burst: 20
};

// Implement rate limiting
class RateLimiter {
  private requests: Map<string, number[]> = new Map();

  isAllowed(key: string, limit: number, windowMs: number): boolean {
    const now = Date.now();
    const requests = this.requests.get(key) || [];
    
    // Remove old requests outside window
    const validRequests = requests.filter(time => now - time < windowMs);
    
    if (validRequests.length >= limit) {
      return false;
    }
    
    validRequests.push(now);
    this.requests.set(key, validRequests);
    return true;
  }
}
```

### Caching Strategy

```typescript
// SBOM cache implementation
class SBOMCache {
  private cache = new Map<string, CacheEntry>();
  private readonly TTL = 3600000; // 1 hour

  get(key: string): SBOMData | null {
    const entry = this.cache.get(key);
    if (!entry || Date.now() - entry.timestamp > this.TTL) {
      this.cache.delete(key);
      return null;
    }
    return entry.data;
  }

  set(key: string, data: SBOMData): void {
    this.cache.set(key, { data, timestamp: Date.now() });
  }

  invalidate(pattern: string): void {
    for (const key of this.cache.keys()) {
      if (key.includes(pattern)) {
        this.cache.delete(key);
      }
    }
  }
}
```

## Webhook Integration

### SBOM Generation Webhooks

```typescript
// Webhook configuration for automated SBOM generation
interface WebhookConfig {
  url: string;
  secret: string;
  events: ('sbom.generated' | 'vulnerability.detected' | 'agent.updated')[];
}

class SBOMWebhookService {
  async sendWebhook(event: string, data: any, config: WebhookConfig): Promise<void> {
    const payload = {
      event,
      timestamp: new Date().toISOString(),
      data
    };

    const signature = this.generateSignature(JSON.stringify(payload), config.secret);

    await fetch(config.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Wazuh-Signature': signature,
        'X-Wazuh-Event': event
      },
      body: JSON.stringify(payload)
    });
  }

  private generateSignature(payload: string, secret: string): string {
    const crypto = require('crypto');
    return 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');
  }
}
```

## Testing and Validation

### Unit Test Examples

```typescript
import { WazuhSBOMService } from './wazuh-sbom-service';

describe('WazuhSBOMService', () => {
  let service: WazuhSBOMService;
  let mockApiClient: jest.Mocked<WazuhAPIClient>;

  beforeEach(() => {
    mockApiClient = createMockApiClient();
    service = new WazuhSBOMService('https://test-wazuh:55000', mockCredentials);
  });

  describe('generateSBOM', () => {
    it('should generate SBOM with packages and vulnerabilities', async () => {
      // Mock API responses
      mockApiClient.get
        .mockResolvedValueOnce({ data: { affected_items: [mockAgent] } })
        .mockResolvedValueOnce({ data: { affected_items: mockPackages } })
        .mockResolvedValueOnce({ data: { affected_items: [mockOSInfo] } })
        .mockResolvedValueOnce({ data: { affected_items: mockVulnerabilities } });

      const result = await service.generateSBOM('001');

      expect(result).toBeDefined();
      expect(result.agent_id).toBe('001');
      expect(result.packages).toHaveLength(mockPackages.length);
      expect(result.vulnerabilities).toHaveLength(mockVulnerabilities.length);
    });

    it('should handle API errors gracefully', async () => {
      mockApiClient.get.mockRejectedValue(new Error('API unavailable'));

      await expect(service.generateSBOM('001')).rejects.toThrow(SBOMGenerationError);
    });
  });
});
```

## Conclusion

This API reference provides comprehensive documentation for integrating with the Wazuh SBOM system. The APIs are designed to be:

- **RESTful**: Following REST principles for consistency
- **Scalable**: Optimized for large-scale deployments
- **Secure**: Built-in authentication and authorization
- **Extensible**: Easy to extend with additional functionality
- **Well-documented**: Complete with examples and error handling

For additional implementation details, refer to the main integration guide and Wazuh official documentation.