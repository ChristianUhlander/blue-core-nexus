/**
 * GVM/OpenVAS Management Component
 * 
 * This component provides comprehensive vulnerability management:
 * - Vulnerability scanning and assessment
 * - Target management
 * - Scan configuration and scheduling
 * - CVE tracking and reporting
 * 
 * @author Security Dashboard Team
 * @version 1.0.0
 */

import React, { useState, useEffect } from 'react';
import { Eye, Target, Shield, Play, Pause, Download, AlertTriangle, CheckCircle } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { useSecurityStatus } from '@/hooks/useSecurityStatus';
import { securityApiManager } from '@/services/securityApi';

interface VulnerabilityScan {
  id: string;
  name: string;
  target: string;
  status: 'running' | 'completed' | 'failed' | 'paused';
  progress: number;
  started: string;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

interface CVEEntry {
  id: string;
  cve_id: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  score: number;
  description: string;
  affected_hosts: string[];
  published: string;
}

const GVMManagement: React.FC = () => {
  const { toast } = useToast();
  const { getConnectionIndicator, checkServiceConnection } = useSecurityStatus();
  
  const [scans, setScans] = useState<VulnerabilityScan[]>([]);
  const [cves, setCves] = useState<CVEEntry[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [newScanTarget, setNewScanTarget] = useState('');
  
  // Connection status for OpenVAS/GVM service
  const connectionStatus = getConnectionIndicator('openvasgvm');

  /**
   * Load vulnerability scans from GVM
   * In production, this would call a Supabase Edge Function
   */
  const loadScans = async () => {
    setIsLoading(true);
    try {
      const gvmService = securityApiManager.getService('openvas');
      if (!gvmService) {
        throw new Error('GVM service not available');
      }

      // TODO: This will be replaced with actual API call via Supabase Edge Function
      // This would call: /functions/v1/gvm-get-scans
      
      // Mock data for demonstration - remove when API is connected
      const mockScans: VulnerabilityScan[] = [
        {
          id: 'scan001',
          name: 'Web Server Security Scan',
          target: '192.168.1.100-110',
          status: 'running',
          progress: 67,
          started: new Date(Date.now() - 1800000).toISOString(),
          vulnerabilities: { critical: 2, high: 5, medium: 12, low: 23 }
        },
        {
          id: 'scan002',
          name: 'Network Infrastructure Scan',
          target: '10.0.0.0/24',
          status: 'completed',
          progress: 100,
          started: new Date(Date.now() - 7200000).toISOString(),
          vulnerabilities: { critical: 0, high: 3, medium: 8, low: 15 }
        },
        {
          id: 'scan003',
          name: 'Database Server Assessment',
          target: '192.168.1.200',
          status: 'failed',
          progress: 0,
          started: new Date(Date.now() - 3600000).toISOString(),
          vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }
        }
      ];

      setScans(mockScans);
      
      toast({
        title: "Scans Loaded",
        description: `Retrieved ${mockScans.length} vulnerability scans`,
      });
    } catch (error) {
      console.error('Failed to load scans:', error);
      toast({
        title: "Error",
        description: "Failed to load vulnerability scans",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Load CVE entries from GVM
   * In production, this would call a Supabase Edge Function
   */
  const loadCVEs = async () => {
    setIsLoading(true);
    try {
      // TODO: This will be replaced with actual API call via Supabase Edge Function
      // This would call: /functions/v1/gvm-get-cves
      
      // Mock data for demonstration - remove when API is connected
      const mockCVEs: CVEEntry[] = [
        {
          id: 'cve001',
          cve_id: 'CVE-2023-4911',
          severity: 'Critical',
          score: 9.8,
          description: 'Remote code execution in glibc ld.so',
          affected_hosts: ['192.168.1.100', '192.168.1.105'],
          published: '2023-10-03'
        },
        {
          id: 'cve002',
          cve_id: 'CVE-2023-38545',
          severity: 'High',
          score: 8.1,
          description: 'Heap buffer overflow in curl SOCKS5 proxy',
          affected_hosts: ['192.168.1.102', '192.168.1.108'],
          published: '2023-10-11'
        },
        {
          id: 'cve003',
          cve_id: 'CVE-2023-5678',
          severity: 'Medium',
          score: 6.5,
          description: 'Information disclosure in Apache HTTP Server',
          affected_hosts: ['192.168.1.100'],
          published: '2023-11-15'
        }
      ];

      setCves(mockCVEs);
    } catch (error) {
      console.error('Failed to load CVEs:', error);
      toast({
        title: "Error",
        description: "Failed to load CVE data",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Start a new vulnerability scan
   * @param target - Target to scan (IP range, hostname, etc.)
   */
  const startNewScan = async () => {
    if (!newScanTarget.trim()) {
      toast({
        title: "Error",
        description: "Please enter a target to scan",
        variant: "destructive",
      });
      return;
    }

    setIsLoading(true);
    try {
      const gvmService = securityApiManager.getService('openvas');
      if (!gvmService) {
        throw new Error('GVM service not available');
      }

      // TODO: This will be replaced with actual API call via Supabase Edge Function
      // This would call: /functions/v1/gvm-start-scan
      const scanId = await gvmService.startScan('target-001', 'config-001');
      
      const newScan: VulnerabilityScan = {
        id: scanId || `scan${Date.now()}`,
        name: `Scan of ${newScanTarget}`,
        target: newScanTarget,
        status: 'running',
        progress: 0,
        started: new Date().toISOString(),
        vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 }
      };

      setScans(prev => [newScan, ...prev]);
      setNewScanTarget('');
      
      toast({
        title: "Scan Started",
        description: `Vulnerability scan initiated for ${newScanTarget}`,
      });
    } catch (error) {
      console.error('Failed to start scan:', error);
      toast({
        title: "Error",
        description: "Failed to start vulnerability scan",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Pause or resume a scan
   * @param scanId - ID of the scan to control
   * @param action - 'pause' or 'resume'
   */
  const controlScan = async (scanId: string, action: 'pause' | 'resume') => {
    try {
      // TODO: Implement via Supabase Edge Function
      // This would call: /functions/v1/gvm-control-scan
      
      setScans(prev => prev.map(scan => 
        scan.id === scanId 
          ? { ...scan, status: action === 'pause' ? 'paused' : 'running' }
          : scan
      ));
      
      toast({
        title: `Scan ${action === 'pause' ? 'Paused' : 'Resumed'}`,
        description: `Scan ${scanId} has been ${action}d`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: `Failed to ${action} scan`,
        variant: "destructive",
      });
    }
  };

  /**
   * Test connection to GVM
   */
  const testConnection = async () => {
    setIsLoading(true);
    try {
      await checkServiceConnection('openvasgvm');
      toast({
        title: "Connection Test",
        description: "GVM connection test completed",
      });
    } catch (error) {
      toast({
        title: "Connection Failed",
        description: "Unable to connect to GVM/OpenVAS",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Load data on component mount
  useEffect(() => {
    loadScans();
    loadCVEs();
  }, []);

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header with Connection Status */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Eye className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-3xl font-bold text-glow">GVM/OpenVAS Management</h1>
            <p className="text-muted-foreground">Vulnerability Assessment & Management</p>
          </div>
        </div>
        
        {/* Connection Status Indicator */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className={`w-3 h-3 rounded-full ${connectionStatus.color}`} />
            <span className="text-sm font-medium">
              {connectionStatus.status === 'connected' ? 'Connected' : 'Not Connected'}
            </span>
          </div>
          <Button 
            onClick={testConnection} 
            disabled={isLoading}
            size="sm"
            variant="outline"
          >
            <Shield className="h-4 w-4 mr-2" />
            Test Connection
          </Button>
        </div>
      </div>

      {/* Quick Scan Launcher */}
      <Card className="gradient-card glow-hover">
        <CardHeader>
          <CardTitle>Launch New Scan</CardTitle>
          <CardDescription>Start a vulnerability assessment scan</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <div className="flex-1">
              <Label htmlFor="scan-target">Target (IP, range, or hostname)</Label>
              <Input
                id="scan-target"
                placeholder="192.168.1.100 or 10.0.0.0/24"
                value={newScanTarget}
                onChange={(e) => setNewScanTarget(e.target.value)}
              />
            </div>
            <div className="flex items-end">
              <Button 
                onClick={startNewScan} 
                disabled={isLoading || !newScanTarget.trim()}
                className="glow-hover"
              >
                <Play className="h-4 w-4 mr-2" />
                Start Scan
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Main Management Interface */}
      <Tabs defaultValue="scans">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="scans">Active Scans</TabsTrigger>
          <TabsTrigger value="vulnerabilities">CVE Database</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
        </TabsList>

        {/* Active Scans Tab */}
        <TabsContent value="scans" className="space-y-4">
          <div className="grid gap-4">
            {scans.map((scan) => (
              <Card key={scan.id} className="gradient-card">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-lg">{scan.name}</CardTitle>
                      <CardDescription>{scan.target}</CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge 
                        variant={
                          scan.status === 'completed' ? 'default' :
                          scan.status === 'running' ? 'secondary' :
                          scan.status === 'failed' ? 'destructive' : 'outline'
                        }
                      >
                        {scan.status}
                      </Badge>
                      {scan.status === 'running' && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => controlScan(scan.id, 'pause')}
                        >
                          <Pause className="h-4 w-4" />
                        </Button>
                      )}
                      {scan.status === 'paused' && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => controlScan(scan.id, 'resume')}
                        >
                          <Play className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  {scan.status === 'running' && (
                    <div className="mb-4">
                      <div className="flex justify-between text-sm mb-2">
                        <span>Progress</span>
                        <span>{scan.progress}%</span>
                      </div>
                      <Progress value={scan.progress} className="glow" />
                    </div>
                  )}
                  
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Started:</span>
                      <p className="font-medium">
                        {new Date(scan.started).toLocaleString()}
                      </p>
                    </div>
                    <div>
                      <span className="text-red-500">Critical:</span>
                      <p className="font-bold text-red-500">{scan.vulnerabilities.critical}</p>
                    </div>
                    <div>
                      <span className="text-orange-500">High:</span>
                      <p className="font-bold text-orange-500">{scan.vulnerabilities.high}</p>
                    </div>
                    <div>
                      <span className="text-yellow-500">Medium:</span>
                      <p className="font-bold text-yellow-500">{scan.vulnerabilities.medium}</p>
                    </div>
                    <div>
                      <span className="text-blue-500">Low:</span>
                      <p className="font-bold text-blue-500">{scan.vulnerabilities.low}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* CVE Database Tab */}
        <TabsContent value="vulnerabilities" className="space-y-4">
          <div className="space-y-3">
            {cves.map((cve) => (
              <Card key={cve.id} className="gradient-card">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      <AlertTriangle className={`h-5 w-5 mt-0.5 ${
                        cve.severity === 'Critical' ? 'text-red-500' :
                        cve.severity === 'High' ? 'text-orange-500' :
                        cve.severity === 'Medium' ? 'text-yellow-500' : 'text-blue-500'
                      }`} />
                      <div className="space-y-2">
                        <div className="flex items-center gap-3">
                          <h3 className="font-semibold">{cve.cve_id}</h3>
                          <Badge variant={
                            cve.severity === 'Critical' ? 'destructive' :
                            cve.severity === 'High' ? 'default' : 'secondary'
                          }>
                            {cve.severity} ({cve.score})
                          </Badge>
                        </div>
                        <p className="text-sm">{cve.description}</p>
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          <span>Affected hosts: {cve.affected_hosts.length}</span>
                          <span>Published: {cve.published}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Reports Tab */}
        <TabsContent value="reports" className="space-y-4">
          <Card className="gradient-card">
            <CardHeader>
              <CardTitle>Vulnerability Reports</CardTitle>
              <CardDescription>
                Generate and download comprehensive security reports
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-12">
                <Download className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">Report Generation</h3>
                <p className="text-muted-foreground mb-4">
                  Detailed vulnerability reports require API connection
                </p>
                <div className="flex items-center justify-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${connectionStatus.color}`} />
                  <span className="text-sm">{connectionStatus.message}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default GVMManagement;