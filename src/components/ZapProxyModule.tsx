import { useState } from "react";
import { Zap, Play, StopCircle, Shield, AlertTriangle, Download } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";

interface ZapProxyModuleProps {
  sessionId?: string;
}

export const ZapProxyModule = ({ sessionId }: ZapProxyModuleProps) => {
  const { toast } = useToast();
  
  const [scanRunning, setScanRunning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanConfig, setScanConfig] = useState({
    target: 'https://',
    scanType: 'baseline',
    spiderEnabled: true,
    activeScanEnabled: true,
    authEnabled: false,
    authUrl: '',
    username: '',
    password: '',
    excludeUrls: [''],
    includeAlphaRules: false,
    includeBetaRules: false,
    reportFormat: 'html',
    maxDuration: 60
  });

  const handleScanLaunch = async () => {
    if (!scanConfig.target.trim() || !scanConfig.target.startsWith('http')) {
      toast({
        title: "Invalid Target",
        description: "Please enter a valid HTTP/HTTPS URL to scan.",
        variant: "destructive"
      });
      return;
    }

    setScanRunning(true);
    setScanProgress(0);

    try {
      const scanPayload = {
        target: scanConfig.target,
        scanType: scanConfig.scanType,
        options: {
          spider: scanConfig.spiderEnabled,
          activeScan: scanConfig.activeScanEnabled,
          authentication: scanConfig.authEnabled ? {
            url: scanConfig.authUrl,
            username: scanConfig.username,
            password: scanConfig.password
          } : null,
          exclusions: scanConfig.excludeUrls.filter(url => url.trim()),
          includeAlphaRules: scanConfig.includeAlphaRules,
          includeBetaRules: scanConfig.includeBetaRules,
          reportFormat: scanConfig.reportFormat,
          maxDuration: scanConfig.maxDuration
        },
        timestamp: new Date().toISOString(),
        scanId: `zap-scan-${Date.now()}`
      };

      console.log('ZAP Scan initiated with payload:', scanPayload);

      // Simulate scan progress
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 100) {
            clearInterval(progressInterval);
            setScanRunning(false);
            toast({
              title: "ZAP Scan Complete",
              description: `Security scan completed for ${scanConfig.target}. Report generated successfully.`
            });
            return 100;
          }
          return prev + Math.random() * 10;
        });
      }, 1000);

      toast({
        title: "ZAP Scan Started",
        description: `OWASP ZAP scan initiated for ${scanConfig.target}.`
      });
    } catch (error) {
      console.error('ZAP scan failed:', error);
      setScanRunning(false);
      setScanProgress(0);
      toast({
        title: "Scan Failed",
        description: "Failed to start ZAP scan. Check backend configuration.",
        variant: "destructive"
      });
    }
  };

  const handleScanStop = () => {
    setScanRunning(false);
    setScanProgress(0);
    toast({
      title: "Scan Stopped",
      description: "ZAP scan has been terminated."
    });
  };

  const addExcludeUrl = () => {
    setScanConfig({
      ...scanConfig,
      excludeUrls: [...scanConfig.excludeUrls, '']
    });
  };

  const removeExcludeUrl = (index: number) => {
    if (scanConfig.excludeUrls.length > 1) {
      const updatedUrls = scanConfig.excludeUrls.filter((_, i) => i !== index);
      setScanConfig({
        ...scanConfig,
        excludeUrls: updatedUrls
      });
    }
  };

  const handleExcludeUrlChange = (index: number, value: string) => {
    const updatedUrls = [...scanConfig.excludeUrls];
    updatedUrls[index] = value;
    setScanConfig({
      ...scanConfig,
      excludeUrls: updatedUrls
    });
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold flex items-center gap-3">
            <div className="relative">
              <Zap className="h-8 w-8 text-yellow-500 animate-pulse" />
              <div className="absolute -top-1 -right-1 w-3 h-3 bg-yellow-500 rounded-full animate-ping" />
            </div>
            OWASP ZAP Proxy
          </h2>
          <p className="text-muted-foreground mt-2">
            Web Application Security Testing with OWASP ZAP
          </p>
        </div>
        <div className="flex gap-2">
          {!scanRunning ? (
            <Button onClick={handleScanLaunch} className="glow-hover" size="lg">
              <Play className="h-4 w-4 mr-2" />
              Start Scan
            </Button>
          ) : (
            <Button onClick={handleScanStop} variant="destructive" size="lg">
              <StopCircle className="h-4 w-4 mr-2" />
              Stop Scan
            </Button>
          )}
        </div>
      </div>

      {scanRunning && (
        <Card className="gradient-card border-yellow-500/20">
          <CardContent className="p-6">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Scan Progress</span>
                <Badge variant="secondary">{Math.round(scanProgress)}%</Badge>
              </div>
              <Progress value={scanProgress} className="h-2" />
              <p className="text-xs text-muted-foreground">
                Scanning {scanConfig.target}...
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="config" className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="config">Configuration</TabsTrigger>
          <TabsTrigger value="advanced">Advanced Options</TabsTrigger>
          <TabsTrigger value="results">Results</TabsTrigger>
        </TabsList>

        <TabsContent value="config" className="space-y-4">
          <Card className="gradient-card border-primary/20">
            <CardHeader>
              <CardTitle>Scan Configuration</CardTitle>
              <CardDescription>
                Configure your ZAP security scan parameters
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="target">Target URL *</Label>
                <Input
                  id="target"
                  placeholder="https://example.com"
                  value={scanConfig.target}
                  onChange={(e) => setScanConfig({ ...scanConfig, target: e.target.value })}
                  className="font-mono"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="scanType">Scan Type</Label>
                <Select
                  value={scanConfig.scanType}
                  onValueChange={(value) => setScanConfig({ ...scanConfig, scanType: value })}
                >
                  <SelectTrigger id="scanType">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="baseline">Baseline Scan</SelectItem>
                    <SelectItem value="full">Full Scan</SelectItem>
                    <SelectItem value="api">API Scan</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="flex items-center justify-between space-x-2">
                  <Label htmlFor="spider" className="flex-1">Spider/Crawl</Label>
                  <Switch
                    id="spider"
                    checked={scanConfig.spiderEnabled}
                    onCheckedChange={(checked) => setScanConfig({ ...scanConfig, spiderEnabled: checked })}
                  />
                </div>
                <div className="flex items-center justify-between space-x-2">
                  <Label htmlFor="active" className="flex-1">Active Scan</Label>
                  <Switch
                    id="active"
                    checked={scanConfig.activeScanEnabled}
                    onCheckedChange={(checked) => setScanConfig({ ...scanConfig, activeScanEnabled: checked })}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="maxDuration">Max Duration (minutes)</Label>
                <Input
                  id="maxDuration"
                  type="number"
                  value={scanConfig.maxDuration}
                  onChange={(e) => setScanConfig({ ...scanConfig, maxDuration: parseInt(e.target.value) || 60 })}
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="advanced" className="space-y-4">
          <Card className="gradient-card border-primary/20">
            <CardHeader>
              <CardTitle>Advanced Options</CardTitle>
              <CardDescription>
                Authentication, exclusions, and advanced scan settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between space-x-2">
                <Label htmlFor="auth" className="flex-1">Enable Authentication</Label>
                <Switch
                  id="auth"
                  checked={scanConfig.authEnabled}
                  onCheckedChange={(checked) => setScanConfig({ ...scanConfig, authEnabled: checked })}
                />
              </div>

              {scanConfig.authEnabled && (
                <div className="space-y-4 p-4 border border-border/50 rounded-lg">
                  <div className="space-y-2">
                    <Label htmlFor="authUrl">Login URL</Label>
                    <Input
                      id="authUrl"
                      placeholder="https://example.com/login"
                      value={scanConfig.authUrl}
                      onChange={(e) => setScanConfig({ ...scanConfig, authUrl: e.target.value })}
                      className="font-mono"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="username">Username</Label>
                      <Input
                        id="username"
                        value={scanConfig.username}
                        onChange={(e) => setScanConfig({ ...scanConfig, username: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="password">Password</Label>
                      <Input
                        id="password"
                        type="password"
                        value={scanConfig.password}
                        onChange={(e) => setScanConfig({ ...scanConfig, password: e.target.value })}
                      />
                    </div>
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label>Exclude URLs</Label>
                  <Button onClick={addExcludeUrl} variant="outline" size="sm">
                    Add URL
                  </Button>
                </div>
                <div className="space-y-2">
                  {scanConfig.excludeUrls.map((url, index) => (
                    <div key={index} className="flex gap-2">
                      <Input
                        placeholder="https://example.com/logout"
                        value={url}
                        onChange={(e) => handleExcludeUrlChange(index, e.target.value)}
                        className="font-mono"
                      />
                      <Button
                        onClick={() => removeExcludeUrl(index)}
                        variant="outline"
                        size="icon"
                        disabled={scanConfig.excludeUrls.length === 1}
                      >
                        ✕
                      </Button>
                    </div>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="flex items-center justify-between space-x-2">
                  <Label htmlFor="alpha" className="flex-1">Include Alpha Rules</Label>
                  <Switch
                    id="alpha"
                    checked={scanConfig.includeAlphaRules}
                    onCheckedChange={(checked) => setScanConfig({ ...scanConfig, includeAlphaRules: checked })}
                  />
                </div>
                <div className="flex items-center justify-between space-x-2">
                  <Label htmlFor="beta" className="flex-1">Include Beta Rules</Label>
                  <Switch
                    id="beta"
                    checked={scanConfig.includeBetaRules}
                    onCheckedChange={(checked) => setScanConfig({ ...scanConfig, includeBetaRules: checked })}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="reportFormat">Report Format</Label>
                <Select
                  value={scanConfig.reportFormat}
                  onValueChange={(value) => setScanConfig({ ...scanConfig, reportFormat: value })}
                >
                  <SelectTrigger id="reportFormat">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="html">HTML</SelectItem>
                    <SelectItem value="json">JSON</SelectItem>
                    <SelectItem value="xml">XML</SelectItem>
                    <SelectItem value="md">Markdown</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="results" className="space-y-4">
          <Card className="gradient-card border-primary/20">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span>Scan Results</span>
                <Button variant="outline" size="sm">
                  <Download className="h-4 w-4 mr-2" />
                  Download Report
                </Button>
              </CardTitle>
              <CardDescription>
                Security findings and vulnerabilities detected by ZAP
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px]">
                <div className="text-center py-12 text-muted-foreground">
                  <Shield className="h-16 w-16 mx-auto mb-4 opacity-50" />
                  <p className="text-lg font-medium">No Scan Results</p>
                  <p className="text-sm">Run a scan to see security findings here</p>
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};
