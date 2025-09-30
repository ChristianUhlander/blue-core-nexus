import { useState } from "react";
import { Shield, Upload, Search, FileText, AlertTriangle, Target, Database, Download, Filter, X } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";

interface MitreMapping {
  id: string;
  technique: string;
  tactic: string[];
  description: string;
  count: number;
  severity: string;
  timestamp: string;
  agent: string;
}

interface LogAlert {
  rule: {
    id: string;
    level: number;
    description: string;
    mitre?: {
      id: string[];
      tactic: string[];
      technique: string[];
    };
  };
  agent: {
    id: string;
    name: string;
  };
  timestamp: string;
  full_log?: string;
}

export const MitreAttackMapper = () => {
  const { toast } = useToast();
  const [logInput, setLogInput] = useState("");
  const [mappings, setMappings] = useState<MitreMapping[]>([]);
  const [filterTactic, setFilterTactic] = useState("all");
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // MITRE ATT&CK Tactics for filtering
  const tactics = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact"
  ];

  const parseWazuhLogs = (logText: string): LogAlert[] => {
    try {
      // Try to parse as JSON array
      const logs = JSON.parse(logText);
      return Array.isArray(logs) ? logs : [logs];
    } catch {
      // Try to parse line-by-line JSON
      const lines = logText.trim().split('\n');
      const alerts: LogAlert[] = [];
      
      for (const line of lines) {
        try {
          const alert = JSON.parse(line);
          if (alert.rule) {
            alerts.push(alert);
          }
        } catch {
          // Skip invalid lines
        }
      }
      
      return alerts;
    }
  };

  const analyzeLogs = () => {
    if (!logInput.trim()) {
      toast({
        title: "No Logs Provided",
        description: "Please paste Wazuh logs in JSON format to analyze.",
        variant: "destructive"
      });
      return;
    }

    setIsAnalyzing(true);

    try {
      const alerts = parseWazuhLogs(logInput);
      
      if (alerts.length === 0) {
        toast({
          title: "No Valid Logs Found",
          description: "Could not parse any valid Wazuh alerts from the input.",
          variant: "destructive"
        });
        setIsAnalyzing(false);
        return;
      }

      // Extract MITRE ATT&CK mappings
      const mitreMap = new Map<string, MitreMapping>();

      alerts.forEach(alert => {
        if (alert.rule?.mitre?.id) {
          alert.rule.mitre.id.forEach((mitreId, index) => {
            const technique = alert.rule.mitre?.technique?.[index] || "Unknown";
            const tactics = alert.rule.mitre?.tactic || [];
            
            if (mitreMap.has(mitreId)) {
              const existing = mitreMap.get(mitreId)!;
              existing.count += 1;
            } else {
              mitreMap.set(mitreId, {
                id: mitreId,
                technique: technique,
                tactic: tactics,
                description: alert.rule.description,
                count: 1,
                severity: alert.rule.level >= 10 ? "Critical" : alert.rule.level >= 7 ? "High" : alert.rule.level >= 4 ? "Medium" : "Low",
                timestamp: alert.timestamp,
                agent: alert.agent?.name || "Unknown"
              });
            }
          });
        }
      });

      const mappedData = Array.from(mitreMap.values()).sort((a, b) => b.count - a.count);
      setMappings(mappedData);

      toast({
        title: "Analysis Complete",
        description: `Successfully mapped ${mappedData.length} MITRE ATT&CK techniques from ${alerts.length} alerts.`
      });
    } catch (error) {
      console.error("Error analyzing logs:", error);
      toast({
        title: "Analysis Failed",
        description: "Failed to parse logs. Ensure they are in valid Wazuh JSON format.",
        variant: "destructive"
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      setLogInput(text);
      toast({
        title: "File Loaded",
        description: `Loaded ${file.name} successfully.`
      });
    };
    reader.readAsText(file);
  };

  const filteredMappings = mappings.filter(mapping => {
    const matchesTactic = filterTactic === "all" || mapping.tactic.some(t => t.toLowerCase().includes(filterTactic.toLowerCase()));
    const matchesSeverity = filterSeverity === "all" || mapping.severity.toLowerCase() === filterSeverity.toLowerCase();
    const matchesSearch = searchQuery === "" || 
      mapping.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      mapping.technique.toLowerCase().includes(searchQuery.toLowerCase()) ||
      mapping.description.toLowerCase().includes(searchQuery.toLowerCase());
    
    return matchesTactic && matchesSeverity && matchesSearch;
  });

  const getStats = () => {
    return {
      total: mappings.length,
      critical: mappings.filter(m => m.severity === "Critical").length,
      high: mappings.filter(m => m.severity === "High").length,
      unique_tactics: new Set(mappings.flatMap(m => m.tactic)).size
    };
  };

  const stats = getStats();

  const exportResults = () => {
    const data = JSON.stringify(mappings, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mitre-mapping-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    
    toast({
      title: "Export Complete",
      description: "MITRE ATT&CK mapping exported successfully."
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-2xl font-bold flex items-center gap-3">
            <Shield className="h-7 w-7 text-primary" />
            MITRE ATT&CK Log Mapper
          </h3>
          <p className="text-muted-foreground mt-1">
            Import and analyze Wazuh logs to map threats to MITRE ATT&CK framework
          </p>
        </div>
        {mappings.length > 0 && (
          <Button onClick={exportResults} variant="outline" size="sm">
            <Download className="h-4 w-4 mr-2" />
            Export Results
          </Button>
        )}
      </div>

      <Tabs defaultValue="import" className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="import">Import Logs</TabsTrigger>
          <TabsTrigger value="analysis">Analysis</TabsTrigger>
          <TabsTrigger value="visualization">Visualization</TabsTrigger>
        </TabsList>

        <TabsContent value="import" className="space-y-4">
          <Card className="gradient-card border-primary/20">
            <CardHeader>
              <CardTitle>Import Wazuh Logs</CardTitle>
              <CardDescription>
                Upload a log file or paste Wazuh alerts in JSON format for MITRE ATT&CK mapping
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="file-upload">Upload Log File</Label>
                <div className="flex gap-2">
                  <Input
                    id="file-upload"
                    type="file"
                    accept=".json,.log,.txt"
                    onChange={handleFileUpload}
                    className="flex-1"
                  />
                  <Button variant="outline" onClick={() => document.getElementById('file-upload')?.click()}>
                    <Upload className="h-4 w-4 mr-2" />
                    Browse
                  </Button>
                </div>
              </div>

              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-background px-2 text-muted-foreground">Or paste logs</span>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="log-input">Wazuh Alerts (JSON format)</Label>
                <Textarea
                  id="log-input"
                  placeholder='{"rule":{"id":"110011","level":10,"description":"...","mitre":{"id":["T1543.003"],...}},...}'
                  value={logInput}
                  onChange={(e) => setLogInput(e.target.value)}
                  className="font-mono text-sm h-64"
                />
                <p className="text-xs text-muted-foreground">
                  Supported formats: JSON array, newline-delimited JSON (NDJSON), or single alert object
                </p>
              </div>

              <div className="flex justify-between items-center pt-4 border-t">
                <Button variant="outline" onClick={() => setLogInput("")}>
                  <X className="h-4 w-4 mr-2" />
                  Clear
                </Button>
                <Button onClick={analyzeLogs} disabled={isAnalyzing} className="glow-hover">
                  <Target className="h-4 w-4 mr-2" />
                  {isAnalyzing ? "Analyzing..." : "Analyze Logs"}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Example format */}
          <Card className="gradient-card border-blue-500/20">
            <CardHeader>
              <CardTitle className="text-sm">Expected Log Format</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="text-xs bg-muted/50 p-3 rounded-lg overflow-x-auto">
{`{
  "rule": {
    "id": "110011",
    "level": 10,
    "description": "PsExec service running...",
    "mitre": {
      "id": ["T1543.003"],
      "tactic": ["Persistence", "Privilege Escalation"],
      "technique": ["Windows Service"]
    }
  },
  "agent": {
    "id": "001",
    "name": "Windows11"
  },
  "timestamp": "2024-01-15T10:30:45Z"
}`}
              </pre>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="analysis" className="space-y-4">
          {mappings.length === 0 ? (
            <Card className="gradient-card border-primary/20">
              <CardContent className="text-center py-12">
                <Database className="h-16 w-16 mx-auto mb-4 opacity-50" />
                <p className="text-lg font-medium">No Analysis Available</p>
                <p className="text-sm text-muted-foreground mt-2">
                  Import and analyze logs to see MITRE ATT&CK mappings
                </p>
              </CardContent>
            </Card>
          ) : (
            <>
              {/* Statistics */}
              <div className="grid grid-cols-4 gap-4">
                <Card className="gradient-card border-primary/20">
                  <CardContent className="p-4">
                    <div className="text-2xl font-bold text-primary">{stats.total}</div>
                    <div className="text-sm text-muted-foreground">Techniques Detected</div>
                  </CardContent>
                </Card>
                <Card className="gradient-card border-red-500/20">
                  <CardContent className="p-4">
                    <div className="text-2xl font-bold text-red-500">{stats.critical}</div>
                    <div className="text-sm text-muted-foreground">Critical Severity</div>
                  </CardContent>
                </Card>
                <Card className="gradient-card border-orange-500/20">
                  <CardContent className="p-4">
                    <div className="text-2xl font-bold text-orange-500">{stats.high}</div>
                    <div className="text-sm text-muted-foreground">High Severity</div>
                  </CardContent>
                </Card>
                <Card className="gradient-card border-blue-500/20">
                  <CardContent className="p-4">
                    <div className="text-2xl font-bold text-blue-500">{stats.unique_tactics}</div>
                    <div className="text-sm text-muted-foreground">Unique Tactics</div>
                  </CardContent>
                </Card>
              </div>

              {/* Filters */}
              <Card className="gradient-card border-primary/20">
                <CardContent className="p-4">
                  <div className="flex gap-4">
                    <div className="flex-1">
                      <Input
                        placeholder="Search techniques, IDs, or descriptions..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full"
                      />
                    </div>
                    <Select value={filterTactic} onValueChange={setFilterTactic}>
                      <SelectTrigger className="w-[200px]">
                        <SelectValue placeholder="Filter by Tactic" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Tactics</SelectItem>
                        {tactics.map(tactic => (
                          <SelectItem key={tactic} value={tactic}>{tactic}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Select value={filterSeverity} onValueChange={setFilterSeverity}>
                      <SelectTrigger className="w-[150px]">
                        <SelectValue placeholder="Severity" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Severity</SelectItem>
                        <SelectItem value="critical">Critical</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="low">Low</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </CardContent>
              </Card>

              {/* Results Table */}
              <Card className="gradient-card border-primary/20">
                <CardHeader>
                  <CardTitle>MITRE ATT&CK Mappings ({filteredMappings.length})</CardTitle>
                  <CardDescription>
                    Detected techniques mapped to the MITRE ATT&CK framework
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[500px]">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Technique ID</TableHead>
                          <TableHead>Technique</TableHead>
                          <TableHead>Tactics</TableHead>
                          <TableHead>Severity</TableHead>
                          <TableHead>Count</TableHead>
                          <TableHead>Agent</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredMappings.map((mapping) => (
                          <TableRow key={mapping.id + mapping.timestamp}>
                            <TableCell className="font-mono font-bold">{mapping.id}</TableCell>
                            <TableCell>
                              <div>
                                <div className="font-medium">{mapping.technique}</div>
                                <div className="text-xs text-muted-foreground truncate max-w-[300px]">
                                  {mapping.description}
                                </div>
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="flex flex-wrap gap-1">
                                {mapping.tactic.map((tactic, idx) => (
                                  <Badge key={idx} variant="outline" className="text-xs">
                                    {tactic}
                                  </Badge>
                                ))}
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={
                                  mapping.severity === "Critical" ? "destructive" :
                                  mapping.severity === "High" ? "default" :
                                  "secondary"
                                }
                              >
                                {mapping.severity}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline">{mapping.count}x</Badge>
                            </TableCell>
                            <TableCell className="text-sm">{mapping.agent}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>

        <TabsContent value="visualization" className="space-y-4">
          <Card className="gradient-card border-primary/20">
            <CardHeader>
              <CardTitle>Attack Chain Visualization</CardTitle>
              <CardDescription>
                Visual representation of detected MITRE ATT&CK tactics and techniques
              </CardDescription>
            </CardHeader>
            <CardContent>
              {mappings.length === 0 ? (
                <div className="text-center py-12">
                  <Target className="h-16 w-16 mx-auto mb-4 opacity-50" />
                  <p className="text-lg font-medium">No Data to Visualize</p>
                  <p className="text-sm text-muted-foreground mt-2">
                    Analyze logs first to see attack chain visualization
                  </p>
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Tactics Distribution */}
                  <div>
                    <h4 className="text-sm font-semibold mb-3">Tactics Distribution</h4>
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                      {tactics.map(tactic => {
                        const count = mappings.filter(m => m.tactic.includes(tactic)).length;
                        if (count === 0) return null;
                        return (
                          <Card key={tactic} className="gradient-card border-primary/10">
                            <CardContent className="p-3">
                              <div className="text-lg font-bold text-primary">{count}</div>
                              <div className="text-xs text-muted-foreground">{tactic}</div>
                            </CardContent>
                          </Card>
                        );
                      })}
                    </div>
                  </div>

                  {/* Top Techniques */}
                  <div>
                    <h4 className="text-sm font-semibold mb-3">Most Frequent Techniques</h4>
                    <div className="space-y-2">
                      {mappings.slice(0, 10).map((mapping) => (
                        <div key={mapping.id} className="flex items-center gap-3 p-3 rounded-lg bg-muted/20 border border-border/30">
                          <Badge variant="outline" className="font-mono">{mapping.id}</Badge>
                          <div className="flex-1">
                            <div className="font-medium text-sm">{mapping.technique}</div>
                            <div className="text-xs text-muted-foreground">{mapping.tactic.join(", ")}</div>
                          </div>
                          <Badge variant={mapping.severity === "Critical" ? "destructive" : "default"}>
                            {mapping.count}x
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};
