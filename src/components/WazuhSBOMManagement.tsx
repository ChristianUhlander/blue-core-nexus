import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { Textarea } from './ui/textarea';
import { Progress } from './ui/progress';
import { useToast } from '../hooks/use-toast';
import { 
  Package, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Download, 
  Upload, 
  RefreshCw as Refresh, 
  Search,
  FileText,
  Database,
  Bug,
  Activity,
  Zap,
  ExternalLink,
  Filter,
  Clock,
  TrendingUp,
  GitBranch
} from 'lucide-react';

// SBOM Types based on Wazuh Syscollector API
interface SoftwarePackage {
  id: string;
  name: string;
  version: string;
  vendor?: string;
  architecture: string;
  description?: string;
  install_time?: string;
  location?: string;
  size?: number;
  source?: string;
  format?: 'rpm' | 'deb' | 'msi' | 'pkg' | 'other';
}

interface VulnerabilityInfo {
  cve: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  score: number;
  description: string;
  published: string;
  references: string[];
  affected_package: string;
  fixed_version?: string;
}

interface SBOMData {
  id: string;
  agent_id: string;
  agent_name: string;
  generated_at: string;
  format: 'cyclonedx' | 'spdx' | 'wazuh-native';
  packages: SoftwarePackage[];
  vulnerabilities: VulnerabilityInfo[];
  metadata: {
    os: string;
    architecture: string;
    scan_time: string;
    total_packages: number;
    vulnerable_packages: number;
  };
}

interface WazuhAgent {
  id: string;
  name: string;
  ip: string;
  os: string;
  status: 'active' | 'disconnected' | 'never_connected';
  last_keep_alive: string;
  version: string;
}

export const WazuhSBOMManagement: React.FC = () => {
  const [agents, setAgents] = useState<WazuhAgent[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<string>('');
  const [sbomData, setSbomData] = useState<SBOMData | null>(null);
  const [packages, setPackages] = useState<SoftwarePackage[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [scanProgress, setScanProgress] = useState(0);
  const [lastScanTime, setLastScanTime] = useState<string>('');
  const { toast } = useToast();

  // Mock data for demonstration - in production, this would come from Wazuh API
  const mockAgents: WazuhAgent[] = [
    {
      id: '001',
      name: 'web-server-01',
      ip: '192.168.1.10',
      os: 'Ubuntu 20.04 LTS',
      status: 'active',
      last_keep_alive: '2024-01-15T10:30:00Z',
      version: '4.12.0'
    },
    {
      id: '002', 
      name: 'db-server-01',
      ip: '192.168.1.20',
      os: 'CentOS 8',
      status: 'active',
      last_keep_alive: '2024-01-15T10:29:45Z',
      version: '4.12.0'
    },
    {
      id: '003',
      name: 'app-server-01', 
      ip: '192.168.1.30',
      os: 'Windows Server 2019',
      status: 'disconnected',
      last_keep_alive: '2024-01-15T09:15:22Z',
      version: '4.12.0'
    }
  ];

  const mockPackages: SoftwarePackage[] = [
    {
      id: 'pkg-001',
      name: 'openssl',
      version: '1.1.1f-1ubuntu2.19',
      vendor: 'OpenSSL Project',
      architecture: 'amd64',
      description: 'Secure Sockets Layer toolkit - cryptographic utility',
      install_time: '2023-06-15T14:20:00Z',
      location: '/usr/bin/openssl',
      size: 1234567,
      source: 'ubuntu',
      format: 'deb'
    },
    {
      id: 'pkg-002', 
      name: 'nginx',
      version: '1.18.0-0ubuntu1.4',
      vendor: 'Nginx Inc.',
      architecture: 'amd64',
      description: 'HTTP and reverse proxy server',
      install_time: '2023-06-20T09:15:00Z',
      location: '/usr/sbin/nginx',
      size: 2567890,
      source: 'ubuntu',
      format: 'deb'
    },
    {
      id: 'pkg-003',
      name: 'apache2',
      version: '2.4.41-4ubuntu3.14',
      vendor: 'Apache Software Foundation',
      architecture: 'amd64', 
      description: 'Apache HTTP Server',
      install_time: '2023-07-01T16:45:00Z',
      location: '/usr/sbin/apache2',
      size: 3456789,
      source: 'ubuntu',
      format: 'deb'
    }
  ];

  const mockVulnerabilities: VulnerabilityInfo[] = [
    {
      cve: 'CVE-2023-0286',
      severity: 'high',
      score: 7.4,
      description: 'X.400 address type confusion in X.509 GeneralName',
      published: '2023-02-07T00:00:00Z',
      references: ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-0286'],
      affected_package: 'openssl',
      fixed_version: '1.1.1t'
    },
    {
      cve: 'CVE-2023-3446',
      severity: 'medium', 
      score: 5.3,
      description: 'Excessive time spent checking DH keys and parameters',
      published: '2023-07-19T00:00:00Z',
      references: ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-3446'],
      affected_package: 'openssl',
      fixed_version: '1.1.1u'
    }
  ];

  useEffect(() => {
    setAgents(mockAgents);
    if (mockAgents.length > 0) {
      setSelectedAgent(mockAgents[0].id);
    }
  }, []);

  const generateSBOM = async (agentId: string, format: 'cyclonedx' | 'spdx' | 'wazuh-native' = 'cyclonedx') => {
    setLoading(true);
    setScanProgress(0);

    try {
      // Simulate progress
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + 10;
        });
      }, 200);

      // Simulate API calls to Wazuh Syscollector
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Mock SBOM generation
      const agent = agents.find(a => a.id === agentId);
      if (!agent) throw new Error('Agent not found');

      const sbom: SBOMData = {
        id: `sbom-${Date.now()}`,
        agent_id: agentId,
        agent_name: agent.name,
        generated_at: new Date().toISOString(),
        format,
        packages: mockPackages,
        vulnerabilities: mockVulnerabilities,
        metadata: {
          os: agent.os,
          architecture: 'x86_64',
          scan_time: new Date().toISOString(),
          total_packages: mockPackages.length,
          vulnerable_packages: mockVulnerabilities.length
        }
      };

      setSbomData(sbom);
      setPackages(mockPackages);
      setVulnerabilities(mockVulnerabilities);
      setLastScanTime(new Date().toLocaleString());
      setScanProgress(100);

      toast({
        title: "SBOM Generated Successfully",
        description: `Generated ${format.toUpperCase()} SBOM for ${agent.name} with ${mockPackages.length} packages`,
      });

    } catch (error) {
      toast({
        title: "Error Generating SBOM", 
        description: "Failed to generate Software Bill of Materials. Check Wazuh connection.",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
      setTimeout(() => setScanProgress(0), 1000);
    }
  };

  const exportSBOM = (format: 'json' | 'xml' | 'csv') => {
    if (!sbomData) {
      toast({
        title: "No SBOM Data",
        description: "Please generate an SBOM first",
        variant: "destructive",
      });
      return;
    }

    let content = '';
    let filename = `sbom-${sbomData.agent_name}-${new Date().getTime()}`;

    switch (format) {
      case 'json':
        content = JSON.stringify(sbomData, null, 2);
        filename += '.json';
        break;
      case 'xml':
        // Simple CycloneDX XML representation
        content = `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
  <metadata>
    <timestamp>${sbomData.generated_at}</timestamp>
    <component type="operating-system" bom-ref="${sbomData.agent_id}">
      <name>${sbomData.agent_name}</name>
    </component>
  </metadata>
  <components>
    ${sbomData.packages.map(pkg => `
    <component type="library" bom-ref="${pkg.id}">
      <name>${pkg.name}</name>
      <version>${pkg.version}</version>
      <description>${pkg.description || ''}</description>
    </component>`).join('')}
  </components>
</bom>`;
        filename += '.xml';
        break;
      case 'csv':
        const csvHeaders = 'Package Name,Version,Vendor,Architecture,Description,Install Time,CVEs\n';
        const csvRows = sbomData.packages.map(pkg => {
          const relatedCVEs = sbomData.vulnerabilities
            .filter(vuln => vuln.affected_package === pkg.name)
            .map(vuln => vuln.cve)
            .join(';');
          return `"${pkg.name}","${pkg.version}","${pkg.vendor || ''}","${pkg.architecture}","${pkg.description || ''}","${pkg.install_time || ''}","${relatedCVEs}"`;
        }).join('\n');
        content = csvHeaders + csvRows;
        filename += '.csv';
        break;
    }

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast({
      title: "SBOM Exported",
      description: `Successfully exported SBOM as ${format.toUpperCase()}`,
    });
  };

  const refreshInventory = async () => {
    if (!selectedAgent) return;
    
    setLoading(true);
    toast({
      title: "Refreshing Inventory",
      description: "Fetching latest package information from agent...",
    });

    // Simulate API call to trigger Syscollector scan
    await new Promise(resolve => setTimeout(resolve, 1500));
    await generateSBOM(selectedAgent);
  };

  const filteredPackages = packages.filter(pkg =>
    pkg.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    pkg.description?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    if (severityFilter !== 'all' && vuln.severity !== severityFilter) return false;
    return vuln.cve.toLowerCase().includes(searchTerm.toLowerCase()) ||
           vuln.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
           vuln.affected_package.toLowerCase().includes(searchTerm.toLowerCase());
  });

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500 text-white';
      case 'high': return 'bg-orange-500 text-white';
      case 'medium': return 'bg-yellow-500 text-black';
      case 'low': return 'bg-blue-500 text-white';
      default: return 'bg-muted';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <p className="text-muted-foreground">
            Generate and manage software inventories with vulnerability correlation
          </p>
        </div>
        
        {lastScanTime && (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Clock className="h-4 w-4" />
            Last scan: {lastScanTime}
          </div>
        )}
      </div>

      {/* Agent Selection */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            Agent Selection
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label>Select Agent</Label>
              <Select value={selectedAgent} onValueChange={setSelectedAgent}>
                <SelectTrigger>
                  <SelectValue placeholder="Choose an agent" />
                </SelectTrigger>
                <SelectContent>
                  {agents.map(agent => (
                    <SelectItem key={agent.id} value={agent.id}>
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${
                          agent.status === 'active' ? 'bg-green-500' : 'bg-red-500'
                        }`} />
                        {agent.name} ({agent.ip})
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>SBOM Format</Label>
              <Select defaultValue="cyclonedx">
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="cyclonedx">CycloneDX</SelectItem>
                  <SelectItem value="spdx">SPDX</SelectItem>
                  <SelectItem value="wazuh-native">Wazuh Native</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-end gap-2">
              <Button 
                onClick={() => selectedAgent && generateSBOM(selectedAgent)}
                disabled={!selectedAgent || loading}
                className="flex-1"
              >
                {loading ? (
                  <>
                    <Activity className="h-4 w-4 mr-2 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Zap className="h-4 w-4 mr-2" />
                    Generate SBOM
                  </>
                )}
              </Button>
              
              <Button
                variant="outline"
                onClick={refreshInventory}
                disabled={!selectedAgent || loading}
              >
                <Refresh className="h-4 w-4" />
              </Button>
            </div>
          </div>

          {scanProgress > 0 && (
            <div className="mt-4 space-y-2">
              <div className="flex justify-between text-sm">
                <span>Scanning packages and vulnerabilities...</span>
                <span>{scanProgress}%</span>
              </div>
              <Progress value={scanProgress} className="w-full" />
            </div>
          )}
        </CardContent>
      </Card>

      {/* SBOM Management Tabs */}
      {sbomData && (
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList className="grid grid-cols-4 w-full">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="packages">Packages</TabsTrigger>
            <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
            <TabsTrigger value="export">Export</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Package className="h-4 w-4" />
                    Total Packages
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{sbomData.metadata.total_packages}</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    Software components detected
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Bug className="h-4 w-4" />
                    Vulnerable Packages
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-orange-500">
                    {sbomData.metadata.vulnerable_packages}
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    Packages with known CVEs
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Shield className="h-4 w-4" />
                    Security Score
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-green-500">
                    {Math.round((1 - sbomData.metadata.vulnerable_packages / sbomData.metadata.total_packages) * 100)}%
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    Based on vulnerability ratio
                  </p>
                </CardContent>
              </Card>
            </div>

            {/* Agent Information */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-5 w-5" />
                  Agent Information
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <div className="font-medium text-muted-foreground">Agent Name</div>
                    <div>{sbomData.agent_name}</div>
                  </div>
                  <div>
                    <div className="font-medium text-muted-foreground">Operating System</div>
                    <div>{sbomData.metadata.os}</div>
                  </div>
                  <div>
                    <div className="font-medium text-muted-foreground">Architecture</div>
                    <div>{sbomData.metadata.architecture}</div>
                  </div>
                  <div>
                    <div className="font-medium text-muted-foreground">Scan Time</div>
                    <div>{new Date(sbomData.metadata.scan_time).toLocaleString()}</div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Quick Actions */}
            <Card>
              <CardHeader>
                <CardTitle>Quick Actions</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                  <Button variant="outline" onClick={() => exportSBOM('json')}>
                    <Download className="h-4 w-4 mr-2" />
                    Export JSON
                  </Button>
                  <Button variant="outline" onClick={() => exportSBOM('xml')}>
                    <FileText className="h-4 w-4 mr-2" />
                    Export XML
                  </Button>
                  <Button variant="outline" onClick={() => exportSBOM('csv')}>
                    <FileText className="h-4 w-4 mr-2" />
                    Export CSV
                  </Button>
                  <Button variant="outline" onClick={refreshInventory}>
                    <Refresh className="h-4 w-4 mr-2" />
                    Refresh Scan
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Packages Tab */}
          <TabsContent value="packages" className="space-y-4">
            <div className="flex gap-4">
              <div className="flex-1">
                <Input
                  placeholder="Search packages..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full"
                />
              </div>
              <Button variant="outline">
                <Filter className="h-4 w-4 mr-2" />
                Filter
              </Button>
            </div>

            <div className="space-y-2">
              {filteredPackages.map(pkg => (
                <Card key={pkg.id} className="hover:bg-accent/50 transition-colors">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <h4 className="font-medium">{pkg.name}</h4>
                          <Badge variant="outline">{pkg.version}</Badge>
                          <Badge variant="secondary" className="text-xs">
                            {pkg.format}
                          </Badge>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          {pkg.description}
                        </p>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span>Vendor: {pkg.vendor || 'Unknown'}</span>
                          <span>Architecture: {pkg.architecture}</span>
                          <span>Size: {pkg.size ? `${Math.round(pkg.size / 1024)} KB` : 'Unknown'}</span>
                        </div>
                      </div>
                      
                      <div className="flex items-center gap-2">
                        {vulnerabilities.some(v => v.affected_package === pkg.name) ? (
                          <Badge variant="destructive" className="text-xs">
                            <AlertTriangle className="h-3 w-3 mr-1" />
                            Vulnerable
                          </Badge>
                        ) : (
                          <Badge className="text-xs bg-green-500">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Secure
                          </Badge>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          {/* Vulnerabilities Tab */}
          <TabsContent value="vulnerabilities" className="space-y-4">
            <div className="flex gap-4">
              <div className="flex-1">
                <Input
                  placeholder="Search vulnerabilities..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full"
                />
              </div>
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              {filteredVulnerabilities.map(vuln => (
                <Card key={vuln.cve} className="hover:bg-accent/50 transition-colors">
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between">
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          <h4 className="font-medium">{vuln.cve}</h4>
                          <Badge className={getSeverityColor(vuln.severity)}>
                            {vuln.severity.toUpperCase()}
                          </Badge>
                          <Badge variant="outline">Score: {vuln.score}</Badge>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          {vuln.description}
                        </p>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span>Affected: {vuln.affected_package}</span>
                          <span>Published: {new Date(vuln.published).toLocaleDateString()}</span>
                          {vuln.fixed_version && (
                            <span className="text-green-600">
                              Fixed in: {vuln.fixed_version}
                            </span>
                          )}
                        </div>
                      </div>
                      
                      <Button variant="ghost" size="sm">
                        <ExternalLink className="h-4 w-4" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          {/* Export Tab */}
          <TabsContent value="export" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Export Options</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Card className="cursor-pointer hover:bg-accent/50 transition-colors" 
                        onClick={() => exportSBOM('json')}>
                    <CardContent className="p-4 text-center">
                      <FileText className="h-8 w-8 mx-auto mb-2 text-primary" />
                      <h4 className="font-medium">JSON Format</h4>
                      <p className="text-xs text-muted-foreground mt-1">
                        Standard JSON SBOM with full metadata
                      </p>
                    </CardContent>
                  </Card>

                  <Card className="cursor-pointer hover:bg-accent/50 transition-colors"
                        onClick={() => exportSBOM('xml')}>
                    <CardContent className="p-4 text-center">
                      <FileText className="h-8 w-8 mx-auto mb-2 text-primary" />
                      <h4 className="font-medium">CycloneDX XML</h4>
                      <p className="text-xs text-muted-foreground mt-1">
                        Industry standard XML format
                      </p>
                    </CardContent>
                  </Card>

                  <Card className="cursor-pointer hover:bg-accent/50 transition-colors"
                        onClick={() => exportSBOM('csv')}>
                    <CardContent className="p-4 text-center">
                      <FileText className="h-8 w-8 mx-auto mb-2 text-primary" />
                      <h4 className="font-medium">CSV Format</h4>
                      <p className="text-xs text-muted-foreground mt-1">
                        Spreadsheet-compatible format
                      </p>
                    </CardContent>
                  </Card>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
};