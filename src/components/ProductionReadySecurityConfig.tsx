import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { toast } from '@/hooks/use-toast';
import { 
  Clock, 
  RefreshCw, 
  Shield, 
  CheckCircle, 
  Settings, 
  Ticket,
  Target,
  Play,
  RotateCcw,
  ExternalLink
} from 'lucide-react';
import { format } from 'date-fns';
import { cn } from '@/lib/utils';

interface AttackPlan {
  id: string;
  name: string;
  description: string;
  schedule: 'daily' | 'weekly' | 'monthly' | 'custom';
  enabled: boolean;
  lastRun?: Date;
  nextRun?: Date;
  status: 'idle' | 'running' | 'completed' | 'failed';
  categories: string[];
  targets: string[];
}

interface TicketingConfig {
  provider: 'jira' | 'servicenow' | 'custom';
  enabled: boolean;
  apiUrl: string;
  credentials: {
    username: string;
    token: string;
  };
  projectKey: string;
  issueType: string;
  priority: string;
  autoAssign: boolean;
  assignee?: string;
}

interface RemediationTracking {
  ticketId: string;
  vulnerabilityId: string;
  status: 'open' | 'in_progress' | 'resolved' | 'verified' | 'reopened';
  assignedTo: string;
  createdAt: Date;
  updatedAt: Date;
  verificationAttempts: number;
  autoRetest: boolean;
  retestSchedule?: Date;
}

export const ProductionReadySecurityConfig: React.FC = () => {
  const [activeTab, setActiveTab] = useState('attack-plans');
  const [attackPlans, setAttackPlans] = useState<AttackPlan[]>([
    {
      id: '1',
      name: 'Daily Web App Scan',
      description: 'Automated OWASP Top 10 vulnerability scanning for web applications',
      schedule: 'daily',
      enabled: true,
      lastRun: new Date(Date.now() - 24 * 60 * 60 * 1000),
      nextRun: new Date(Date.now() + 1 * 60 * 60 * 1000),
      status: 'completed',
      categories: ['web-application', 'owasp-top10', 'sql-injection'],
      targets: ['app.company.com', 'api.company.com']
    },
    {
      id: '2',
      name: 'Weekly Infrastructure Audit',
      description: 'Comprehensive network and infrastructure penetration testing',
      schedule: 'weekly',
      enabled: true,
      lastRun: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      nextRun: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
      status: 'idle',
      categories: ['network', 'infrastructure', 'port-scanning'],
      targets: ['10.0.0.0/24', 'production-vpc']
    },
    {
      id: '3',
      name: 'API Security Assessment',
      description: 'Comprehensive REST/GraphQL API security testing including authentication bypass, injection attacks, and business logic flaws',
      schedule: 'weekly',
      enabled: true,
      lastRun: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
      nextRun: new Date(Date.now() + 4 * 24 * 60 * 60 * 1000),
      status: 'idle',
      categories: ['api-security', 'rest-api', 'graphql', 'authentication-bypass', 'injection'],
      targets: ['api.company.com/v1', 'api.company.com/v2', 'graphql.company.com']
    },
    {
      id: '4',
      name: 'Social Engineering Simulation',
      description: 'Automated phishing campaigns and social engineering tests to assess human security awareness',
      schedule: 'monthly',
      enabled: true,
      lastRun: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000),
      nextRun: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000),
      status: 'completed',
      categories: ['social-engineering', 'phishing', 'awareness-testing', 'human-factor'],
      targets: ['employees@company.com', 'contractors@company.com']
    },
    {
      id: '5',
      name: 'Wireless Network Penetration',
      description: 'WiFi security assessment including WPA/WEP cracking, rogue access point detection, and wireless client attacks',
      schedule: 'weekly',
      enabled: false,
      lastRun: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
      nextRun: new Date(Date.now() + 4 * 24 * 60 * 60 * 1000),
      status: 'idle',
      categories: ['wireless', 'wifi-security', 'wpa-cracking', 'rogue-ap-detection'],
      targets: ['Corporate-WiFi', 'Guest-Network', 'IoT-Devices-WiFi']
    },
    {
      id: '6',  
      name: 'Cloud Infrastructure Security',
      description: 'AWS/Azure/GCP security assessment including IAM misconfigurations, storage bucket exposure, and container security',
      schedule: 'daily',
      enabled: true,
      lastRun: new Date(Date.now() - 12 * 60 * 60 * 1000),
      nextRun: new Date(Date.now() + 12 * 60 * 60 * 1000),
      status: 'running',
      categories: ['cloud-security', 'aws-security', 'azure-security', 'iam-assessment', 'container-security'],
      targets: ['aws-prod-account', 'azure-subscription', 'k8s-clusters']
    },
    {
      id: '7',
      name: 'Active Directory Assessment',
      description: 'Windows domain security testing including Kerberoasting, DCSync, Golden Ticket attacks, and privilege escalation',
      schedule: 'weekly',
      enabled: true,
      lastRun: new Date(Date.now() - 6 * 24 * 60 * 60 * 1000),
      nextRun: new Date(Date.now() + 1 * 24 * 60 * 60 * 1000),
      status: 'idle',
      categories: ['active-directory', 'kerberoasting', 'privilege-escalation', 'domain-controller'],
      targets: ['dc01.company.local', 'dc02.company.local', 'corp.company.local']
    },
    {
      id: '8',
      name: 'Mobile Application Security',
      description: 'iOS/Android app security testing including static/dynamic analysis, API abuse, and data storage vulnerabilities',
      schedule: 'monthly',
      enabled: true,
      lastRun: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000),
      nextRun: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000),
      status: 'idle',
      categories: ['mobile-security', 'ios-security', 'android-security', 'static-analysis', 'dynamic-analysis'],
      targets: ['com.company.mobile-app', 'company-ios-app', 'mobile-api.company.com']
    },
    {
      id: '9',
      name: 'IoT Device Security Audit',
      description: 'Internet of Things device security assessment including firmware analysis, protocol security, and device authentication',
      schedule: 'monthly',
      enabled: false,
      lastRun: new Date(Date.now() - 25 * 24 * 60 * 60 * 1000),
      nextRun: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000),
      status: 'idle',
      categories: ['iot-security', 'firmware-analysis', 'protocol-security', 'device-authentication'],
      targets: ['smart-cameras', 'building-sensors', 'industrial-controllers']
    }
  ]);

  const [ticketingConfig, setTicketingConfig] = useState<TicketingConfig>({
    provider: 'jira',
    enabled: false,
    apiUrl: '',
    credentials: { username: '', token: '' },
    projectKey: '',
    issueType: 'Bug',
    priority: 'High',
    autoAssign: false
  });

  const [remediationTracking, setRemediationTracking] = useState<RemediationTracking[]>([
    {
      ticketId: 'SEC-123',
      vulnerabilityId: 'CVE-2024-0001',
      status: 'in_progress',
      assignedTo: 'security-team',
      createdAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
      updatedAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
      verificationAttempts: 2,
      autoRetest: true,
      retestSchedule: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000)
    }
  ]);

  const [newPlanName, setNewPlanName] = useState('');
  const [selectedSchedule, setSelectedSchedule] = useState<'daily' | 'weekly' | 'monthly'>('weekly');
  const [showAddPlan, setShowAddPlan] = useState(false);

  const handleCreateAttackPlan = () => {
    if (!newPlanName.trim()) {
      toast({
        title: "Error",
        description: "Please enter a plan name",
        variant: "destructive",
      });
      return;
    }

    const newPlan: AttackPlan = {
      id: Date.now().toString(),
      name: newPlanName,
      description: `Automated ${selectedSchedule} security assessment`,
      schedule: selectedSchedule,
      enabled: true,
      status: 'idle',
      categories: [],
      targets: []
    };

    setAttackPlans([...attackPlans, newPlan]);
    setNewPlanName('');
    setShowAddPlan(false);

    toast({
      title: "Success",
      description: "Attack plan created successfully",
    });
  };

  const togglePlanStatus = (planId: string) => {
    setAttackPlans(plans =>
      plans.map(plan =>
        plan.id === planId ? { ...plan, enabled: !plan.enabled } : plan
      )
    );
  };

  const runPlanNow = (planId: string) => {
    setAttackPlans(plans =>
      plans.map(plan =>
        plan.id === planId ? { 
          ...plan, 
          status: 'running',
          lastRun: new Date()
        } : plan
      )
    );

    toast({
      title: "Attack Plan Started",
      description: "Security scan is now running...",
    });

    setTimeout(() => {
      setAttackPlans(plans =>
        plans.map(plan =>
          plan.id === planId ? { 
            ...plan, 
            status: 'completed',
            nextRun: new Date(Date.now() + (plan.schedule === 'daily' ? 24 : 7 * 24) * 60 * 60 * 1000)
          } : plan
        )
      );
    }, 3000);
  };

  const saveTicketingConfig = () => {
    toast({
      title: "Configuration Saved",
      description: "Ticketing integration settings have been updated",
    });
  };

  const retestVulnerability = (trackingId: string) => {
    setRemediationTracking(tracking =>
      tracking.map(item =>
        item.ticketId === trackingId ? {
          ...item,
          verificationAttempts: item.verificationAttempts + 1,
          updatedAt: new Date()
        } : item
      )
    );

    toast({
      title: "Retest Initiated",
      description: "Vulnerability verification scan started",
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'bg-blue-500';
      case 'completed': return 'bg-green-500';
      case 'failed': return 'bg-red-500';
      case 'in_progress': return 'bg-yellow-500';
      case 'resolved': return 'bg-green-500';
      case 'verified': return 'bg-emerald-500';
      case 'reopened': return 'bg-orange-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Production Security Center</h2>
          <p className="text-muted-foreground">
            Continuous find-fix-verify security operations with automated ticketing
          </p>
        </div>
        <Badge variant="outline" className="text-sm">
          <Shield className="w-4 h-4 mr-1" />
          Production Ready
        </Badge>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="attack-plans" className="flex items-center gap-2">
            <Target className="w-4 h-4" />
            Attack Plans
          </TabsTrigger>
          <TabsTrigger value="ticketing" className="flex items-center gap-2">
            <Ticket className="w-4 h-4" />
            Ticketing
          </TabsTrigger>
          <TabsTrigger value="remediation" className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4" />
            Remediation
          </TabsTrigger>
          <TabsTrigger value="monitoring" className="flex items-center gap-2">
            <RefreshCw className="w-4 h-4" />
            Monitoring
          </TabsTrigger>
        </TabsList>

        <TabsContent value="attack-plans" className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold">Continuous Attack Plans</h3>
            <Button onClick={() => setShowAddPlan(true)}>
              <Play className="w-4 h-4 mr-2" />
              Create Plan
            </Button>
          </div>

          {showAddPlan && (
            <Card>
              <CardHeader>
                <CardTitle>Create New Attack Plan</CardTitle>
                <CardDescription>
                  Set up automated security testing with continuous monitoring
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="plan-name">Plan Name</Label>
                    <Input
                      id="plan-name"
                      value={newPlanName}
                      onChange={(e) => setNewPlanName(e.target.value)}
                      placeholder="e.g., Daily API Security Scan"
                    />
                  </div>
                  <div>
                    <Label htmlFor="schedule">Schedule</Label>
                    <Select value={selectedSchedule} onValueChange={(value: any) => setSelectedSchedule(value)}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="daily">Daily</SelectItem>
                        <SelectItem value="weekly">Weekly</SelectItem>
                        <SelectItem value="monthly">Monthly</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button onClick={handleCreateAttackPlan}>Create Plan</Button>
                  <Button variant="outline" onClick={() => setShowAddPlan(false)}>Cancel</Button>
                </div>
              </CardContent>
            </Card>
          )}

          <div className="grid gap-4">
            {attackPlans.map((plan) => (
              <Card key={plan.id}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        {plan.name}
                        <Badge className={cn("text-xs", getStatusColor(plan.status))}>
                          {plan.status}
                        </Badge>
                      </CardTitle>
                      <CardDescription>{plan.description}</CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={plan.enabled}
                        onCheckedChange={() => togglePlanStatus(plan.id)}
                      />
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => runPlanNow(plan.id)}
                        disabled={plan.status === 'running'}
                      >
                        <Play className="w-4 h-4 mr-1" />
                        Run Now
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <Label className="text-xs text-muted-foreground">Schedule</Label>
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {plan.schedule}
                      </div>
                    </div>
                    <div>
                      <Label className="text-xs text-muted-foreground">Last Run</Label>
                      <div>{plan.lastRun ? format(plan.lastRun, 'MMM dd, HH:mm') : 'Never'}</div>
                    </div>
                    <div>
                      <Label className="text-xs text-muted-foreground">Next Run</Label>
                      <div>{plan.nextRun ? format(plan.nextRun, 'MMM dd, HH:mm') : 'Not scheduled'}</div>
                    </div>
                    <div>
                      <Label className="text-xs text-muted-foreground">Targets</Label>
                      <div>{plan.targets.length} configured</div>
                    </div>
                  </div>
                  {plan.categories.length > 0 && (
                    <div className="mt-3">
                      <div className="flex flex-wrap gap-1">
                        {plan.categories.map((category) => (
                          <Badge key={category} variant="secondary" className="text-xs">
                            {category}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="ticketing" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Ticketing Integration</CardTitle>
              <CardDescription>
                Automatically create and manage security tickets in your preferred system
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center space-x-2">
                <Switch
                  checked={ticketingConfig.enabled}
                  onCheckedChange={(enabled) =>
                    setTicketingConfig({ ...ticketingConfig, enabled })
                  }
                />
                <Label>Enable automatic ticket creation</Label>
              </div>

              <Separator />

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="provider">Ticketing Provider</Label>
                  <Select
                    value={ticketingConfig.provider}
                    onValueChange={(value: any) =>
                      setTicketingConfig({ ...ticketingConfig, provider: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="jira">Jira</SelectItem>
                      <SelectItem value="servicenow">ServiceNow</SelectItem>
                      <SelectItem value="custom">Custom API</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label htmlFor="api-url">API URL</Label>
                  <Input
                    id="api-url"
                    value={ticketingConfig.apiUrl}
                    onChange={(e) =>
                      setTicketingConfig({ ...ticketingConfig, apiUrl: e.target.value })
                    }
                    placeholder="https://company.atlassian.net"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="username">Username/Email</Label>
                  <Input
                    id="username"
                    value={ticketingConfig.credentials.username}
                    onChange={(e) =>
                      setTicketingConfig({
                        ...ticketingConfig,
                        credentials: { ...ticketingConfig.credentials, username: e.target.value }
                      })
                    }
                    placeholder="user@company.com"
                  />
                </div>
                <div>
                  <Label htmlFor="token">API Token</Label>
                  <Input
                    id="token"
                    type="password"
                    value={ticketingConfig.credentials.token}
                    onChange={(e) =>
                      setTicketingConfig({
                        ...ticketingConfig,
                        credentials: { ...ticketingConfig.credentials, token: e.target.value }
                      })
                    }
                    placeholder="API token or password"
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <Label htmlFor="project-key">Project Key</Label>
                  <Input
                    id="project-key"
                    value={ticketingConfig.projectKey}
                    onChange={(e) =>
                      setTicketingConfig({ ...ticketingConfig, projectKey: e.target.value })
                    }
                    placeholder="SEC"
                  />
                </div>
                <div>
                  <Label htmlFor="issue-type">Issue Type</Label>
                  <Select
                    value={ticketingConfig.issueType}
                    onValueChange={(value) =>
                      setTicketingConfig({ ...ticketingConfig, issueType: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Bug">Bug</SelectItem>
                      <SelectItem value="Security">Security</SelectItem>
                      <SelectItem value="Task">Task</SelectItem>
                      <SelectItem value="Story">Story</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label htmlFor="priority">Default Priority</Label>
                  <Select
                    value={ticketingConfig.priority}
                    onValueChange={(value) =>
                      setTicketingConfig({ ...ticketingConfig, priority: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Critical">Critical</SelectItem>
                      <SelectItem value="High">High</SelectItem>
                      <SelectItem value="Medium">Medium</SelectItem>
                      <SelectItem value="Low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <Button onClick={saveTicketingConfig}>
                <Settings className="w-4 h-4 mr-2" />
                Save Configuration
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="remediation" className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold">Remediation Tracking</h3>
            <Badge variant="outline">
              {remediationTracking.length} active tickets
            </Badge>
          </div>

          <div className="grid gap-4">
            {remediationTracking.map((item) => (
              <Card key={item.ticketId}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <ExternalLink className="w-4 h-4" />
                        {item.ticketId}
                        <Badge className={cn("text-xs", getStatusColor(item.status))}>
                          {item.status}
                        </Badge>
                      </CardTitle>
                      <CardDescription>
                        Vulnerability: {item.vulnerabilityId}
                      </CardDescription>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => retestVulnerability(item.ticketId)}
                    >
                      <RotateCcw className="w-4 h-4 mr-1" />
                      Retest
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <Label className="text-xs text-muted-foreground">Assigned To</Label>
                      <div>{item.assignedTo}</div>
                    </div>
                    <div>
                      <Label className="text-xs text-muted-foreground">Created</Label>
                      <div>{format(item.createdAt, 'MMM dd, yyyy')}</div>
                    </div>
                    <div>
                      <Label className="text-xs text-muted-foreground">Verification Attempts</Label>
                      <div>{item.verificationAttempts}</div>
                    </div>
                    <div>
                      <Label className="text-xs text-muted-foreground">Next Retest</Label>
                      <div>
                        {item.retestSchedule ? format(item.retestSchedule, 'MMM dd, HH:mm') : 'Manual'}
                      </div>
                    </div>
                  </div>
                  <div className="mt-3 flex items-center gap-2">
                    <Switch
                      checked={item.autoRetest}
                      onCheckedChange={() => {}}
                    />
                    <Label className="text-sm">Auto-retest when marked resolved</Label>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="monitoring" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <RefreshCw className="w-5 h-5 text-primary" />
                  Active Scans
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {attackPlans.filter(p => p.status === 'running').length}
                </div>
                <p className="text-sm text-muted-foreground">Currently running</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Ticket className="w-5 h-5 text-accent" />
                  Open Tickets
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {remediationTracking.filter(t => ['open', 'in_progress'].includes(t.status)).length}
                </div>
                <p className="text-sm text-muted-foreground">Need attention</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <CheckCircle className="w-5 h-5 text-primary" />
                  Verified Fixes
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {remediationTracking.filter(t => t.status === 'verified').length}
                </div>
                <p className="text-sm text-muted-foreground">This month</p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>System Health</CardTitle>
              <CardDescription>
                Monitor the overall health of your continuous security operations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                    <span>Scanning Engine</span>
                  </div>
                  <Badge variant="outline" className="text-primary">Online</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 bg-primary rounded-full"></div>
                    <span>Ticketing Integration</span>
                  </div>
                  <Badge variant="outline" className="text-primary">Connected</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 bg-accent rounded-full"></div>
                    <span>Verification Engine</span>
                  </div>
                  <Badge variant="outline" className="text-accent">Partial</Badge>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};