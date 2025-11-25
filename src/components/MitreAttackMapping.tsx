/**
 * MITRE ATT&CK Framework Mapping Component
 * 
 * Visualizes security events mapped to MITRE ATT&CK techniques and tactics
 * Integrates with Wazuh alerts to provide threat intelligence context
 */

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { 
  Shield, 
  Target, 
  TrendingUp, 
  AlertTriangle,
  ExternalLink,
  Search,
  Filter,
  Download,
  RefreshCw
} from "lucide-react";
import { toast } from "@/hooks/use-toast";

// MITRE ATT&CK Tactics (14 primary tactics)
const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', description: 'Gather information for planning attacks' },
  { id: 'TA0042', name: 'Resource Development', description: 'Establish resources to support operations' },
  { id: 'TA0001', name: 'Initial Access', description: 'Gain initial foothold in the network' },
  { id: 'TA0002', name: 'Execution', description: 'Execute malicious code' },
  { id: 'TA0003', name: 'Persistence', description: 'Maintain presence in the system' },
  { id: 'TA0004', name: 'Privilege Escalation', description: 'Gain higher-level permissions' },
  { id: 'TA0005', name: 'Defense Evasion', description: 'Avoid detection' },
  { id: 'TA0006', name: 'Credential Access', description: 'Steal credentials' },
  { id: 'TA0007', name: 'Discovery', description: 'Understand the environment' },
  { id: 'TA0008', name: 'Lateral Movement', description: 'Move through the network' },
  { id: 'TA0009', name: 'Collection', description: 'Gather data of interest' },
  { id: 'TA0011', name: 'Command and Control', description: 'Communicate with compromised systems' },
  { id: 'TA0010', name: 'Exfiltration', description: 'Steal data' },
  { id: 'TA0040', name: 'Impact', description: 'Disrupt availability or integrity' }
];

interface MitreTechnique {
  id: string;
  name: string;
  tactics: string[];
  count: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  lastSeen: string;
  alerts: Array<{
    id: string;
    timestamp: string;
    description: string;
    agent: string;
  }>;
}

interface MitreAttackMappingProps {
  className?: string;
}

export const MitreAttackMapping: React.FC<MitreAttackMappingProps> = ({ className }) => {
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedTactic, setSelectedTactic] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [timeRange, setTimeRange] = useState('24h');

  // Mock data - replace with actual API call to Wazuh/backend
  useEffect(() => {
    loadMitreData();
  }, [timeRange]);

  const loadMitreData = async () => {
    setLoading(true);
    try {
      // Use mock data for demonstration
      const mockTechniques: MitreTechnique[] = [
        {
          id: 'T1566.001',
          name: 'Spearphishing Attachment',
          tactics: ['Initial Access'],
          count: 12,
          severity: 'critical',
          lastSeen: new Date().toISOString(),
          alerts: [
            { id: '1', timestamp: new Date().toISOString(), description: 'Suspicious email attachment detected', agent: 'Agent-001' }
          ]
        },
        {
          id: 'T1059.001',
          name: 'PowerShell',
          tactics: ['Execution'],
          count: 8,
          severity: 'high',
          lastSeen: new Date().toISOString(),
          alerts: []
        },
        {
          id: 'T1055',
          name: 'Process Injection',
          tactics: ['Defense Evasion', 'Privilege Escalation'],
          count: 5,
          severity: 'high',
          lastSeen: new Date().toISOString(),
          alerts: []
        },
        {
          id: 'T1486',
          name: 'Data Encrypted for Impact',
          tactics: ['Impact'],
          count: 3,
          severity: 'critical',
          lastSeen: new Date().toISOString(),
          alerts: []
        },
        {
          id: 'T1083',
          name: 'File and Directory Discovery',
          tactics: ['Discovery'],
          count: 15,
          severity: 'medium',
          lastSeen: new Date().toISOString(),
          alerts: []
        }
      ];

      setTechniques(mockTechniques);
      
      toast({
        title: "MITRE Data Loaded",
        description: "Showing example MITRE ATT&CK mappings",
        variant: "default"
      });
    } finally {
      setLoading(false);
    }
  };

  const filteredTechniques = techniques.filter(tech => {
    const matchesSearch = searchQuery === '' || 
      tech.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tech.id.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesTactic = selectedTactic === 'all' || 
      tech.tactics.some(t => t.toLowerCase().includes(selectedTactic.toLowerCase()));
    
    return matchesSearch && matchesTactic;
  });

  const getTacticStats = () => {
    const stats = new Map<string, number>();
    techniques.forEach(tech => {
      tech.tactics.forEach(tactic => {
        stats.set(tactic, (stats.get(tactic) || 0) + tech.count);
      });
    });
    return stats;
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      case 'low': return 'secondary';
      default: return 'outline';
    }
  };

  const tacticStats = getTacticStats();

  return (
    <div className={className}>
      <Card className="gradient-card border-primary/20">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" />
                MITRE ATT&CK Mapping
              </CardTitle>
              <CardDescription>
                Security events mapped to MITRE ATT&CK framework techniques
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Select value={timeRange} onValueChange={setTimeRange}>
                <SelectTrigger className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1h">Last Hour</SelectItem>
                  <SelectItem value="24h">Last 24h</SelectItem>
                  <SelectItem value="7d">Last 7 days</SelectItem>
                  <SelectItem value="30d">Last 30 days</SelectItem>
                </SelectContent>
              </Select>
              <Button 
                size="sm" 
                variant="outline" 
                onClick={loadMitreData}
                disabled={loading}
              >
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="techniques" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="techniques">Techniques</TabsTrigger>
              <TabsTrigger value="tactics">Tactics</TabsTrigger>
              <TabsTrigger value="matrix">ATT&CK Matrix</TabsTrigger>
            </TabsList>

            <TabsContent value="techniques" className="mt-4">
              <div className="space-y-4">
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder="Search techniques..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-8"
                    />
                  </div>
                  <Select value={selectedTactic} onValueChange={setSelectedTactic}>
                    <SelectTrigger className="w-48">
                      <SelectValue placeholder="Filter by tactic" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Tactics</SelectItem>
                      {MITRE_TACTICS.map(tactic => (
                        <SelectItem key={tactic.id} value={tactic.name}>
                          {tactic.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <ScrollArea className="h-[500px]">
                  <div className="space-y-3">
                    {filteredTechniques.map(technique => (
                      <Card key={technique.id} className="border-primary/10">
                        <CardContent className="p-4">
                          <div className="flex items-start justify-between">
                            <div className="space-y-2 flex-1">
                              <div className="flex items-center gap-2">
                                <Badge variant="outline" className="font-mono">
                                  {technique.id}
                                </Badge>
                                <Badge variant={getSeverityColor(technique.severity)}>
                                  {technique.severity}
                                </Badge>
                                <span className="font-semibold">{technique.name}</span>
                              </div>
                              <div className="flex flex-wrap gap-1">
                                {technique.tactics.map((tactic, idx) => (
                                  <Badge key={idx} variant="secondary" className="text-xs">
                                    {tactic}
                                  </Badge>
                                ))}
                              </div>
                              <div className="flex items-center gap-4 text-sm text-muted-foreground">
                                <span className="flex items-center gap-1">
                                  <AlertTriangle className="h-3 w-3" />
                                  {technique.count} events
                                </span>
                                <span>
                                  Last seen: {new Date(technique.lastSeen).toLocaleString()}
                                </span>
                              </div>
                            </div>
                            <Button 
                              size="sm" 
                              variant="ghost"
                              onClick={() => window.open(`https://attack.mitre.org/techniques/${technique.id}`, '_blank')}
                            >
                              <ExternalLink className="h-4 w-4" />
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                    {filteredTechniques.length === 0 && (
                      <div className="text-center py-8 text-muted-foreground">
                        No techniques found matching your filters
                      </div>
                    )}
                  </div>
                </ScrollArea>
              </div>
            </TabsContent>

            <TabsContent value="tactics" className="mt-4">
              <ScrollArea className="h-[500px]">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {MITRE_TACTICS.map(tactic => {
                    const count = tacticStats.get(tactic.name) || 0;
                    return (
                      <Card key={tactic.id} className="border-primary/10">
                        <CardContent className="p-4">
                          <div className="space-y-2">
                            <div className="flex items-start justify-between">
                              <div>
                                <Badge variant="outline" className="font-mono mb-2">
                                  {tactic.id}
                                </Badge>
                                <h4 className="font-semibold">{tactic.name}</h4>
                                <p className="text-sm text-muted-foreground">
                                  {tactic.description}
                                </p>
                              </div>
                              <Badge variant="secondary" className="ml-2">
                                {count} events
                              </Badge>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              </ScrollArea>
            </TabsContent>

            <TabsContent value="matrix" className="mt-4">
              <Card className="border-primary/10">
                <CardContent className="p-6">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-lg font-semibold">MITRE ATT&CK Matrix Overview</h3>
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => window.open('https://attack.mitre.org/', '_blank')}
                      >
                        <ExternalLink className="h-4 w-4 mr-2" />
                        View Full Matrix
                      </Button>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <Card className="bg-primary/5">
                        <CardContent className="p-4 text-center">
                          <div className="text-3xl font-bold text-primary">
                            {techniques.length}
                          </div>
                          <div className="text-sm text-muted-foreground mt-1">
                            Active Techniques
                          </div>
                        </CardContent>
                      </Card>
                      <Card className="bg-destructive/5">
                        <CardContent className="p-4 text-center">
                          <div className="text-3xl font-bold text-destructive">
                            {techniques.filter(t => t.severity === 'critical').length}
                          </div>
                          <div className="text-sm text-muted-foreground mt-1">
                            Critical Techniques
                          </div>
                        </CardContent>
                      </Card>
                      <Card className="bg-secondary/5">
                        <CardContent className="p-4 text-center">
                          <div className="text-3xl font-bold">
                            {tacticStats.size}
                          </div>
                          <div className="text-sm text-muted-foreground mt-1">
                            Tactics Observed
                          </div>
                        </CardContent>
                      </Card>
                      <Card className="bg-accent/5">
                        <CardContent className="p-4 text-center">
                          <div className="text-3xl font-bold">
                            {techniques.reduce((sum, t) => sum + t.count, 0)}
                          </div>
                          <div className="text-sm text-muted-foreground mt-1">
                            Total Events
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                    <div className="mt-6 p-4 bg-muted/50 rounded-lg">
                      <p className="text-sm text-muted-foreground">
                        The MITRE ATT&CK framework is a globally-accessible knowledge base of adversary tactics and techniques 
                        based on real-world observations. This mapping helps correlate security events with known attack patterns.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default MitreAttackMapping;
