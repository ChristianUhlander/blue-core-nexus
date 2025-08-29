import React, { useState } from 'react';
import { 
  Shield, 
  Users, 
  Settings, 
  FileText, 
  AlertTriangle, 
  Activity, 
  Server, 
  Database,
  Search,
  Play,
  Pause,
  Trash2,
  Plus,
  Download,
  Upload,
  Eye,
  RefreshCw,
  ArrowLeft,
  Network,
  Computer,
  Copy,
  Check
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';

const WazuhManagement = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [isAddAgentOpen, setIsAddAgentOpen] = useState(false);
  const [agentForm, setAgentForm] = useState({
    name: '',
    ip: '',
    os: 'linux',
    group: 'default',
    description: ''
  });
  const [copied, setCopied] = useState(false);
  const [isCreateRuleOpen, setIsCreateRuleOpen] = useState(false);
  const [ruleForm, setRuleForm] = useState({
    name: '',
    level: 'medium',
    category: 'authentication',
    template: '',
    description: '',
    customRule: ''
  });
  const { toast } = useToast();

  /**
   * Predefined rule templates based on common security scenarios
   * Organized by threat level and category for easy selection
   */
  const ruleTemplates = {
    low: {
      authentication: [
        {
          id: 'auth_success',
          name: 'Successful Authentication',
          description: 'Monitor successful login attempts for audit purposes',
          rule: `<rule id="100001" level="3">
  <if_sid>5715</if_sid>
  <description>SSH authentication success.</description>
  <mitre>
    <id>T1078</id>
  </mitre>
  <group>authentication_success,pci_dss_10.2.5,gpg13_7.1,gpg13_7.2,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,tsc_CC6.8,</group>
</rule>`
        },
        {
          id: 'user_login',
          name: 'User Login Events',
          description: 'Track all user login events for compliance',
          rule: `<rule id="100002" level="3">
  <if_sid>5501</if_sid>
  <description>User login.</description>
  <group>authentication_success,pci_dss_10.2.5,gpg13_7.8,gdpr_IV_32.2,hipaa_164.312.b,</group>
</rule>`
        }
      ],
      system: [
        {
          id: 'file_access',
          name: 'File Access Monitoring',
          description: 'Monitor file access for audit trails',
          rule: `<rule id="100003" level="2">
  <if_sid>550</if_sid>
  <field name="file">/etc|/bin|/sbin</field>
  <description>File accessed in system directory.</description>
  <group>syscheck,pci_dss_11.5,nist_800_53_SI.7,</group>
</rule>`
        }
      ]
    },
    medium: {
      authentication: [
        {
          id: 'multiple_auth_failures',
          name: 'Multiple Authentication Failures',
          description: 'Detect potential brute force attacks',
          rule: `<rule id="100010" level="7">
  <if_matched_sid>5716</if_matched_sid>
  <same_source_ip />
  <description>Multiple authentication failures from same source IP.</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,gpg13_7.1,</group>
</rule>`
        },
        {
          id: 'privilege_escalation',
          name: 'Privilege Escalation Attempt',
          description: 'Detect attempts to gain elevated privileges',
          rule: `<rule id="100011" level="8">
  <if_sid>5402</if_sid>
  <match>su|sudo</match>
  <description>Privilege escalation attempt detected.</description>
  <mitre>
    <id>T1548</id>
  </mitre>
  <group>privilege_escalation,pci_dss_10.2.2,</group>
</rule>`
        }
      ],
      network: [
        {
          id: 'port_scan',
          name: 'Port Scan Detection',
          description: 'Identify network reconnaissance attempts',
          rule: `<rule id="100012" level="6">
  <if_sid>4001</if_sid>
  <match>port scan</match>
  <description>Port scan detected from external source.</description>
  <mitre>
    <id>T1046</id>
  </mitre>
  <group>recon,pci_dss_11.4,</group>
</rule>`
        }
      ],
      web: [
        {
          id: 'sql_injection',
          name: 'SQL Injection Attempt',
          description: 'Detect SQL injection attack patterns',
          rule: `<rule id="100013" level="7">
  <if_sid>31100</if_sid>
  <match>union select|drop table|insert into</match>
  <description>SQL injection attempt detected.</description>
  <mitre>
    <id>T1190</id>
  </mitre>
  <group>web_attack,pci_dss_6.5.1,</group>
</rule>`
        }
      ]
    },
    high: {
      malware: [
        {
          id: 'malware_execution',
          name: 'Malware Execution',
          description: 'Detect known malware signatures and behavior',
          rule: `<rule id="100020" level="12">
  <if_sid>554</if_sid>
  <match>trojan|backdoor|keylogger|ransomware</match>
  <description>Malware execution detected - immediate response required.</description>
  <mitre>
    <id>T1055</id>
  </mitre>
  <group>malware,pci_dss_5.1,</group>
</rule>`
        },
        {
          id: 'crypto_mining',
          name: 'Cryptocurrency Mining',
          description: 'Detect unauthorized cryptocurrency mining activities',
          rule: `<rule id="100021" level="10">
  <if_sid>2902</if_sid>
  <match>xmrig|cryptonight|monero|bitcoin</match>
  <description>Cryptocurrency mining activity detected.</description>
  <mitre>
    <id>T1496</id>
  </mitre>
  <group>cryptomining,</group>
</rule>`
        }
      ],
      exfiltration: [
        {
          id: 'data_exfiltration',
          name: 'Data Exfiltration',
          description: 'Detect large data transfers indicating potential data theft',
          rule: `<rule id="100022" level="11">
  <if_sid>2830</if_sid>
  <match>large file transfer|bulk download</match>
  <description>Potential data exfiltration detected - large data transfer.</description>
  <mitre>
    <id>T1041</id>
  </mitre>
  <group>data_exfiltration,pci_dss_3.4,</group>
</rule>`
        }
      ],
      system: [
        {
          id: 'rootkit_detection',
          name: 'Rootkit Detection',
          description: 'Identify rootkit installation attempts',
          rule: `<rule id="100023" level="13">
  <if_sid>510</if_sid>
  <match>rootkit|kernel module|system call hook</match>
  <description>Rootkit installation detected - critical system compromise.</description>
  <mitre>
    <id>T1014</id>
  </mitre>
  <group>rootkit,</group>
</rule>`
        }
      ]
    }
  };

  // Mock data - replace with actual Wazuh API calls
  const agents = [
    { id: '001', name: 'web-server-01', ip: '192.168.1.10', os: 'Ubuntu 20.04', status: 'active', lastSeen: '2 min ago' },
    { id: '002', name: 'db-server-01', ip: '192.168.1.11', os: 'CentOS 8', status: 'active', lastSeen: '5 min ago' },
    { id: '003', name: 'mail-server-01', ip: '192.168.1.12', os: 'Windows Server 2019', status: 'disconnected', lastSeen: '2 hours ago' },
  ];

  const rules = [
    { id: '100001', level: 'High', description: 'SSH authentication success', groups: ['authentication', 'ssh'] },
    { id: '100002', level: 'Medium', description: 'Multiple authentication failures', groups: ['authentication', 'brute_force'] },
    { id: '100003', level: 'Low', description: 'User login', groups: ['authentication', 'login'] },
  ];

  const alerts = [
    { id: 1, timestamp: '2024-01-20 14:30:15', agent: 'web-server-01', rule: 'SSH Brute Force', level: 'High', ip: '203.0.113.1' },
    { id: 2, timestamp: '2024-01-20 14:25:32', agent: 'db-server-01', rule: 'Root login', level: 'Medium', ip: '192.168.1.100' },
    { id: 3, timestamp: '2024-01-20 14:20:45', agent: 'mail-server-01', rule: 'File integrity', level: 'Low', ip: '192.168.1.12' },
  ];

  /**
   * Handles adding a new Wazuh agent
   * Validates the form data and generates installation command
   */
  const handleAddAgent = () => {
    if (!agentForm.name || !agentForm.ip) {
      toast({
        title: "Validation Error",
        description: "Agent name and IP address are required",
        variant: "destructive",
      });
      return;
    }

    // In a real implementation, this would make an API call to the Wazuh manager
    // POST /agents with the agent configuration
    toast({
      title: "Agent Configuration Ready",
      description: `Agent ${agentForm.name} configured for IP ${agentForm.ip}. Installation command generated.`,
    });
    
    // Reset form and close dialog
    setAgentForm({ name: '', ip: '', os: 'linux', group: 'default', description: '' });
    setIsAddAgentOpen(false);
  };

  /**
   * Generates the Wazuh agent installation command
   * This would typically be provided by the Wazuh API after agent registration
   */
  const generateInstallCommand = () => {
    const managerIp = "192.168.1.100"; // This would come from configuration
    const agentKey = "MDA4IGFnZW50LTAxIDEwLjAuMC4xMDA"; // This would be generated by Wazuh manager
    
    if (agentForm.os === 'linux') {
      return `curl -so wazuh-agent-4.7.0.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb && sudo WAZUH_MANAGER='${managerIp}' WAZUH_AGENT_NAME='${agentForm.name}' dpkg -i ./wazuh-agent-4.7.0.deb`;
    } else if (agentForm.os === 'windows') {
      return `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile wazuh-agent-4.7.0.msi; msiexec.exe /i wazuh-agent-4.7.0.msi /q WAZUH_MANAGER='${managerIp}' WAZUH_AGENT_NAME='${agentForm.name}'`;
    } else {
      return `pkg install wazuh-agent && echo 'WAZUH_MANAGER="${managerIp}"' >> /usr/local/etc/wazuh-agent.conf && echo 'WAZUH_AGENT_NAME="${agentForm.name}"' >> /usr/local/etc/wazuh-agent.conf`;
    }
  };

  /**
   * Copies the installation command to clipboard
   */
  const copyInstallCommand = async () => {
    const command = generateInstallCommand();
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      toast({
        title: "Copied to clipboard",
        description: "Installation command has been copied to your clipboard",
      });
    } catch (err) {
      toast({
        title: "Copy failed",
        description: "Failed to copy to clipboard. Please select and copy manually.",
        variant: "destructive",
      });
    }
  };

  /**
   * Handles creating a new Wazuh detection rule
   * Validates the rule configuration and submits to Wazuh manager
   */
  const handleCreateRule = () => {
    if (!ruleForm.name || (!ruleForm.template && !ruleForm.customRule)) {
      toast({
        title: "Validation Error",
        description: "Rule name and either a template or custom rule content are required",
        variant: "destructive",
      });
      return;
    }

    // In a real implementation, this would make an API call to the Wazuh manager
    // POST /rules with the rule configuration
    toast({
      title: "Rule Created Successfully",
      description: `Detection rule "${ruleForm.name}" has been created and activated.`,
    });
    
    // Reset form and close dialog
    setRuleForm({ name: '', level: 'medium', category: 'authentication', template: '', description: '', customRule: '' });
    setIsCreateRuleOpen(false);
  };

  /**
   * Gets the selected template rule content
   */
  const getSelectedTemplate = () => {
    if (!ruleForm.template) return null;
    
    const levelTemplates = ruleTemplates[ruleForm.level as keyof typeof ruleTemplates];
    const categoryTemplates = levelTemplates?.[ruleForm.category as keyof typeof levelTemplates] as any[];
    
    return categoryTemplates?.find(template => template.id === ruleForm.template) || null;
  };

  /**
   * Gets available templates for the selected level and category
   */
  const getAvailableTemplates = () => {
    const levelTemplates = ruleTemplates[ruleForm.level as keyof typeof ruleTemplates];
    const categoryTemplates = levelTemplates?.[ruleForm.category as keyof typeof levelTemplates] as any[];
    return categoryTemplates || [];
  };

  /**
   * Copies rule content to clipboard
   */
  const copyRuleContent = async () => {
    const template = getSelectedTemplate();
    const content = template?.rule || ruleForm.customRule;
    
    try {
      await navigator.clipboard.writeText(content);
      toast({
        title: "Copied to clipboard",
        description: "Rule content has been copied to your clipboard",
      });
    } catch (err) {
      toast({
        title: "Copy failed",
        description: "Failed to copy to clipboard. Please select and copy manually.",
        variant: "destructive",
      });
    }
  };

  return (
    <div className="min-h-screen gradient-bg p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-primary glow" />
            <h1 className="text-4xl font-bold text-glow">Wazuh SIEM Management</h1>
          </div>
          <Button
            variant="outline"
            onClick={() => window.location.href = '/'}
            className="glow-hover border-primary/50 hover:border-primary text-primary hover:bg-primary/10"
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            ← Back to Main Dashboard
          </Button>
        </div>
        <p className="text-muted-foreground text-lg">
          Comprehensive security monitoring and incident response management
        </p>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <Card className="gradient-card glow-hover">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Agents</CardTitle>
            <Users className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-primary">247</div>
            <p className="text-xs text-muted-foreground">+12 from last week</p>
          </CardContent>
        </Card>

        <Card className="gradient-card glow-hover">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Alerts</CardTitle>
            <AlertTriangle className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">23</div>
            <p className="text-xs text-muted-foreground">-5 from yesterday</p>
          </CardContent>
        </Card>

        <Card className="gradient-card glow-hover">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Rules Active</CardTitle>
            <FileText className="h-4 w-4 text-secondary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-secondary">1,847</div>
            <p className="text-xs text-muted-foreground">Custom + Default</p>
          </CardContent>
        </Card>

        <Card className="gradient-card glow-hover">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">System Health</CardTitle>
            <Activity className="h-4 w-4 text-accent" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-accent">98.7%</div>
            <Progress value={98.7} className="mt-2" />
          </CardContent>
        </Card>
      </div>

      {/* Main Management Tabs */}
      <Tabs defaultValue="agents" className="space-y-6">
        <TabsList className="grid w-full grid-cols-6 gradient-card">
          <TabsTrigger value="agents" className="flex items-center gap-2">
            <Server className="h-4 w-4" />
            Agents
          </TabsTrigger>
          <TabsTrigger value="rules" className="flex items-center gap-2">
            <FileText className="h-4 w-4" />
            Rules
          </TabsTrigger>
          <TabsTrigger value="alerts" className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            Alerts
          </TabsTrigger>
          <TabsTrigger value="monitoring" className="flex items-center gap-2">
            <Activity className="h-4 w-4" />
            Monitoring
          </TabsTrigger>
          <TabsTrigger value="config" className="flex items-center gap-2">
            <Settings className="h-4 w-4" />
            Configuration
          </TabsTrigger>
          <TabsTrigger value="reports" className="flex items-center gap-2">
            <Database className="h-4 w-4" />
            Reports
          </TabsTrigger>
        </TabsList>

        {/* Agents Management */}
        <TabsContent value="agents" className="space-y-6">
          <Card className="gradient-card glow">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Server className="h-5 w-5 text-primary" />
                    Agent Management
                  </CardTitle>
                  <CardDescription>Monitor and control Wazuh agents across your infrastructure</CardDescription>
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" className="glow-hover">
                    <Download className="h-4 w-4 mr-2" />
                    Deploy Agent
                  </Button>
                  
                  <Dialog open={isAddAgentOpen} onOpenChange={setIsAddAgentOpen}>
                    <DialogTrigger asChild>
                      <Button className="glow-hover">
                        <Plus className="h-4 w-4 mr-2" />
                        Add Agent
                      </Button>
                    </DialogTrigger>
                    <DialogContent className="sm:max-w-[600px] gradient-card">
                      <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                          <Server className="h-5 w-5 text-primary" />
                          Add New Wazuh Agent
                        </DialogTitle>
                        <DialogDescription>
                          Configure a new agent to monitor your infrastructure. Fill in the details and get the installation command.
                        </DialogDescription>
                      </DialogHeader>
                      
                      <div className="grid gap-6 py-4">
                        {/* Agent Basic Information */}
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label htmlFor="agent-name">Agent Name *</Label>
                            <Input
                              id="agent-name"
                              placeholder="web-server-01"
                              value={agentForm.name}
                              onChange={(e) => setAgentForm({...agentForm, name: e.target.value})}
                              className="glow-hover"
                            />
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="agent-ip">IP Address *</Label>
                            <Input
                              id="agent-ip"
                              placeholder="192.168.1.100"
                              value={agentForm.ip}
                              onChange={(e) => setAgentForm({...agentForm, ip: e.target.value})}
                              className="glow-hover"
                            />
                          </div>
                        </div>
                        
                        {/* Operating System and Group */}
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label htmlFor="agent-os">Operating System</Label>
                            <Select value={agentForm.os} onValueChange={(value) => setAgentForm({...agentForm, os: value})}>
                              <SelectTrigger className="glow-hover">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="linux">Linux</SelectItem>
                                <SelectItem value="windows">Windows</SelectItem>
                                <SelectItem value="macos">macOS</SelectItem>
                                <SelectItem value="freebsd">FreeBSD</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="agent-group">Agent Group</Label>
                            <Select value={agentForm.group} onValueChange={(value) => setAgentForm({...agentForm, group: value})}>
                              <SelectTrigger className="glow-hover">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="default">Default</SelectItem>
                                <SelectItem value="web-servers">Web Servers</SelectItem>
                                <SelectItem value="db-servers">Database Servers</SelectItem>
                                <SelectItem value="mail-servers">Mail Servers</SelectItem>
                                <SelectItem value="workstations">Workstations</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        </div>
                        
                        {/* Description */}
                        <div className="space-y-2">
                          <Label htmlFor="agent-description">Description (Optional)</Label>
                          <Textarea
                            id="agent-description"
                            placeholder="Production web server hosting main application"
                            value={agentForm.description}
                            onChange={(e) => setAgentForm({...agentForm, description: e.target.value})}
                            className="glow-hover"
                            rows={3}
                          />
                        </div>
                        
                        {/* Installation Command Preview */}
                        {agentForm.name && agentForm.ip && (
                          <div className="space-y-2">
                            <Label>Installation Command</Label>
                            <div className="relative">
                              <pre className="bg-muted p-3 rounded-md text-sm overflow-x-auto border">
                                <code>{generateInstallCommand()}</code>
                              </pre>
                              <Button
                                size="sm"
                                variant="outline"
                                className="absolute top-2 right-2"
                                onClick={copyInstallCommand}
                              >
                                {copied ? (
                                  <Check className="h-3 w-3" />
                                ) : (
                                  <Copy className="h-3 w-3" />
                                )}
                              </Button>
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Run this command on the target system to install and configure the Wazuh agent.
                            </p>
                          </div>
                        )}
                      </div>
                      
                      <div className="flex justify-end gap-2">
                        <Button variant="outline" onClick={() => setIsAddAgentOpen(false)}>
                          Cancel
                        </Button>
                        <Button onClick={handleAddAgent} className="glow-hover">
                          <Network className="h-4 w-4 mr-2" />
                          Configure Agent
                        </Button>
                      </div>
                    </DialogContent>
                  </Dialog>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-4 mb-4">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input 
                    placeholder="Search agents..." 
                    className="pl-10"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </div>
                <Button variant="outline" className="glow-hover">
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Refresh
                </Button>
              </div>

              <ScrollArea className="h-[400px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Agent ID</TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>IP Address</TableHead>
                      <TableHead>OS</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Last Seen</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {agents.map((agent) => (
                      <TableRow key={agent.id}>
                        <TableCell className="font-mono">{agent.id}</TableCell>
                        <TableCell className="font-medium">{agent.name}</TableCell>
                        <TableCell>{agent.ip}</TableCell>
                        <TableCell>{agent.os}</TableCell>
                        <TableCell>
                          <Badge variant={agent.status === 'active' ? 'default' : 'destructive'}>
                            {agent.status}
                          </Badge>
                        </TableCell>
                        <TableCell>{agent.lastSeen}</TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            <Button size="sm" variant="outline">
                              <Eye className="h-3 w-3" />
                            </Button>
                            <Button size="sm" variant="outline">
                              <Pause className="h-3 w-3" />
                            </Button>
                            <Button size="sm" variant="outline">
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Rules Management */}
        <TabsContent value="rules" className="space-y-6">
          <Card className="gradient-card glow">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <FileText className="h-5 w-5 text-primary" />
                    Detection Rules
                  </CardTitle>
                  <CardDescription>Manage detection rules and custom signatures</CardDescription>
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" className="glow-hover">
                    <Upload className="h-4 w-4 mr-2" />
                    Import Rules
                  </Button>
                  
                  <Dialog open={isCreateRuleOpen} onOpenChange={setIsCreateRuleOpen}>
                    <DialogTrigger asChild>
                      <Button className="glow-hover">
                        <Plus className="h-4 w-4 mr-2" />
                        Create Rule
                      </Button>
                    </DialogTrigger>
                    <DialogContent className="sm:max-w-[700px] max-h-[80vh] overflow-y-auto gradient-card">
                      <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                          <FileText className="h-5 w-5 text-primary" />
                          Create Detection Rule
                        </DialogTitle>
                        <DialogDescription>
                          Create custom detection rules or use predefined templates based on common security scenarios.
                        </DialogDescription>
                      </DialogHeader>
                      
                      <div className="grid gap-4 py-4">
                        {/* Rule Basic Information */}
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label htmlFor="rule-name">Rule Name *</Label>
                            <Input
                              id="rule-name"
                              placeholder="SSH Brute Force Detection"
                              value={ruleForm.name}
                              onChange={(e) => setRuleForm({...ruleForm, name: e.target.value})}
                              className="glow-hover"
                            />
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="rule-level">Threat Level</Label>
                            <Select value={ruleForm.level} onValueChange={(value) => setRuleForm({...ruleForm, level: value, template: ''})}>
                              <SelectTrigger className="glow-hover">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent className="bg-popover border border-border z-50">
                                <SelectItem value="low">
                                  <span className="flex items-center gap-2">
                                    <Badge variant="outline" className="text-xs">LOW</Badge>
                                    Informational & Audit
                                  </span>
                                </SelectItem>
                                <SelectItem value="medium">
                                  <span className="flex items-center gap-2">
                                    <Badge variant="secondary" className="text-xs">MEDIUM</Badge>
                                    Security Events
                                  </span>
                                </SelectItem>
                                <SelectItem value="high">
                                  <span className="flex items-center gap-2">
                                    <Badge variant="destructive" className="text-xs">HIGH</Badge>
                                    Critical Threats
                                  </span>
                                </SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        </div>
                        
                        {/* Category Selection */}
                        <div className="space-y-2">
                          <Label htmlFor="rule-category">Security Category</Label>
                          <Select value={ruleForm.category} onValueChange={(value) => setRuleForm({...ruleForm, category: value, template: ''})}>
                            <SelectTrigger className="glow-hover">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent className="bg-popover border border-border z-50">
                              <SelectItem value="authentication">Authentication & Access</SelectItem>
                              <SelectItem value="system">System Integrity</SelectItem>
                              <SelectItem value="network">Network Security</SelectItem>
                              <SelectItem value="web">Web Application</SelectItem>
                              <SelectItem value="malware">Malware Detection</SelectItem>
                              <SelectItem value="exfiltration">Data Exfiltration</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>

                        {/* Template Selection */}
                        <div className="space-y-2">
                          <Label htmlFor="rule-template">Predefined Template (Optional)</Label>
                          <Select value={ruleForm.template} onValueChange={(value) => setRuleForm({...ruleForm, template: value})}>
                            <SelectTrigger className="glow-hover">
                              <SelectValue placeholder="Choose a template or create custom rule" />
                            </SelectTrigger>
                            <SelectContent className="bg-popover border border-border z-50 max-h-[200px] overflow-y-auto">
                              <SelectItem value="">Custom Rule (No Template)</SelectItem>
                              {getAvailableTemplates().map((template) => (
                                <SelectItem key={template.id} value={template.id}>
                                  {template.name}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                        
                        {/* Description */}
                        <div className="space-y-2">
                          <Label htmlFor="rule-description">Rule Description</Label>
                          <Textarea
                            id="rule-description"
                            placeholder="Describe what this rule detects and when it should trigger..."
                            value={ruleForm.description}
                            onChange={(e) => setRuleForm({...ruleForm, description: e.target.value})}
                            className="glow-hover"
                            rows={2}
                          />
                        </div>
                        
                        {/* Template Preview or Custom Rule Input */}
                        {ruleForm.template ? (
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <Label>Template Rule Content</Label>
                              <Button size="sm" variant="outline" onClick={copyRuleContent}>
                                <Copy className="h-3 w-3 mr-1" />
                                Copy
                              </Button>
                            </div>
                            <div className="bg-muted p-3 rounded-md text-sm overflow-x-auto border max-h-[250px] overflow-y-auto">
                              <pre><code>{getSelectedTemplate()?.rule}</code></pre>
                            </div>
                            <div className="bg-muted/50 p-3 rounded-md">
                              <p className="text-sm text-muted-foreground">
                                <strong>Template:</strong> {getSelectedTemplate()?.name}
                              </p>
                              <p className="text-sm text-muted-foreground mt-1">
                                {getSelectedTemplate()?.description}
                              </p>
                            </div>
                          </div>
                        ) : (
                          <div className="space-y-2">
                            <Label htmlFor="custom-rule">Custom Rule XML *</Label>
                            <Textarea
                              id="custom-rule"
                              placeholder={`<rule id="100050" level="7">
  <if_sid>5716</if_sid>
  <match>authentication failure</match>
  <description>Custom authentication failure rule</description>
  <group>authentication_failures,custom</group>
</rule>`}
                              value={ruleForm.customRule}
                              onChange={(e) => setRuleForm({...ruleForm, customRule: e.target.value})}
                              className="glow-hover font-mono text-sm"
                              rows={8}
                            />
                            <p className="text-xs text-muted-foreground">
                              Enter your custom Wazuh rule in XML format. Use unique rule IDs and appropriate log source references.
                            </p>
                          </div>
                        )}
                        
                        {/* Security Level Guide */}
                        <div className="bg-muted/50 p-3 rounded-md">
                          <h4 className="text-sm font-semibold mb-2">Threat Level Guide</h4>
                          <div className="grid gap-1 text-xs">
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className="text-xs px-1">LOW</Badge>
                              <span>Levels 1-4: Informational events, audit trails</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge variant="secondary" className="text-xs px-1">MED</Badge>
                              <span>Levels 5-8: Security events requiring attention</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge variant="destructive" className="text-xs px-1">HIGH</Badge>
                              <span>Levels 9+: Critical incidents requiring immediate response</span>
                            </div>
                          </div>
                        </div>
                      </div>
                      
                      <div className="flex justify-end gap-2 pt-4">
                        <Button variant="outline" onClick={() => setIsCreateRuleOpen(false)}>
                          Cancel
                        </Button>
                        <Button onClick={handleCreateRule} className="glow-hover">
                          <FileText className="h-4 w-4 mr-2" />
                          Create Rule
                        </Button>
                      </div>
                    </DialogContent>
                  </Dialog>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Rule ID</TableHead>
                      <TableHead>Level</TableHead>
                      <TableHead>Description</TableHead>
                      <TableHead>Groups</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rules.map((rule) => (
                      <TableRow key={rule.id}>
                        <TableCell className="font-mono">{rule.id}</TableCell>
                        <TableCell>
                          <Badge variant={
                            rule.level === 'High' ? 'destructive' : 
                            rule.level === 'Medium' ? 'secondary' : 'outline'
                          }>
                            {rule.level}
                          </Badge>
                        </TableCell>
                        <TableCell>{rule.description}</TableCell>
                        <TableCell>
                          <div className="flex gap-1 flex-wrap">
                            {rule.groups.map((group, index) => (
                              <Badge key={index} variant="outline" className="text-xs">
                                {group}
                              </Badge>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            <Button size="sm" variant="outline">
                              <Eye className="h-3 w-3" />
                            </Button>
                            <Button size="sm" variant="outline">
                              <Settings className="h-3 w-3" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Alerts Management */}
        <TabsContent value="alerts" className="space-y-6">
          <Card className="gradient-card glow">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-primary" />
                Security Alerts
              </CardTitle>
              <CardDescription>Real-time security alerts and incident response</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Agent</TableHead>
                      <TableHead>Rule</TableHead>
                      <TableHead>Level</TableHead>
                      <TableHead>Source IP</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {alerts.map((alert) => (
                      <TableRow key={alert.id}>
                        <TableCell className="font-mono text-sm">{alert.timestamp}</TableCell>
                        <TableCell>{alert.agent}</TableCell>
                        <TableCell>{alert.rule}</TableCell>
                        <TableCell>
                          <Badge variant={
                            alert.level === 'High' ? 'destructive' : 
                            alert.level === 'Medium' ? 'secondary' : 'outline'
                          }>
                            {alert.level}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono">{alert.ip}</TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            <Button size="sm" variant="outline">
                              <Eye className="h-3 w-3" />
                            </Button>
                            <Button size="sm" variant="outline">
                              <Play className="h-3 w-3" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Additional tabs would be implemented similarly */}
        <TabsContent value="monitoring">
          <Card className="gradient-card glow">
            <CardHeader>
              <CardTitle>System Monitoring</CardTitle>
              <CardDescription>Real-time system performance and health metrics</CardDescription>
            </CardHeader>
            <CardContent className="h-[400px] flex items-center justify-center">
              <p className="text-muted-foreground">Monitoring dashboard coming soon...</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="config">
          <Card className="gradient-card glow">
            <CardHeader>
              <CardTitle>Configuration Management</CardTitle>
              <CardDescription>Wazuh server and agent configuration settings</CardDescription>
            </CardHeader>
            <CardContent className="h-[400px] flex items-center justify-center">
              <p className="text-muted-foreground">Configuration panel coming soon...</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="reports">
          <Card className="gradient-card glow">
            <CardHeader>
              <CardTitle>Security Reports</CardTitle>
              <CardDescription>Generate and manage security compliance reports</CardDescription>
            </CardHeader>
            <CardContent className="h-[400px] flex items-center justify-center">
              <p className="text-muted-foreground">Reports dashboard coming soon...</p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <div className="mt-8 text-center">
        <p className="text-sm text-muted-foreground">
          Connect to Supabase to enable Wazuh API integration and real-time functionality
        </p>
      </div>
    </div>
  );
};

export default WazuhManagement;