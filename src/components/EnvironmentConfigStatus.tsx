import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertCircle, CheckCircle, Settings, Key, Database, Shield, Lock } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { config } from "@/config/environment";
import { supabase } from "@/integrations/supabase/client";

interface ConfigStatus {
  name: string;
  status: 'configured' | 'missing' | 'partial';
  details: string;
  icon: any;
  category: string;
}

export const EnvironmentConfigStatus = () => {
  const [configStatuses, setConfigStatuses] = useState<ConfigStatus[]>([]);
  const [hasWarnings, setHasWarnings] = useState(false);

  useEffect(() => {
    checkConfigurations();
  }, []);

  const checkConfigurations = async () => {
    const statuses: ConfigStatus[] = [];

    // Check Supabase configuration
    const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
    const supabaseKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
    
    if (supabaseUrl && supabaseKey) {
      statuses.push({
        name: 'Lovable Cloud',
        status: 'configured',
        details: 'Backend services connected and operational',
        icon: Database,
        category: 'Core Services'
      });
    } else {
      statuses.push({
        name: 'Lovable Cloud',
        status: 'missing',
        details: 'Backend connection not configured',
        icon: Database,
        category: 'Core Services'
      });
    }

    // Check Wazuh configuration
    const wazuhConfig = config.services.wazuh;
    if (wazuhConfig.credentials?.username && wazuhConfig.credentials?.password) {
      statuses.push({
        name: 'Wazuh SIEM',
        status: wazuhConfig.credentials.username === 'wazuh' ? 'partial' : 'configured',
        details: wazuhConfig.credentials.username === 'wazuh' 
          ? 'Using default credentials - update for production' 
          : 'Custom credentials configured',
        icon: Shield,
        category: 'Security Services'
      });
    } else {
      statuses.push({
        name: 'Wazuh SIEM',
        status: 'missing',
        details: 'Credentials not configured',
        icon: Shield,
        category: 'Security Services'
      });
    }

    // Check GVM/OpenVAS configuration
    const gvmConfig = config.services.gvm;
    if (gvmConfig.credentials?.username && gvmConfig.credentials?.password) {
      statuses.push({
        name: 'GVM/OpenVAS',
        status: gvmConfig.credentials.username === 'admin' ? 'partial' : 'configured',
        details: gvmConfig.credentials.username === 'admin'
          ? 'Using default credentials - update for production'
          : 'Custom credentials configured',
        icon: Settings,
        category: 'Security Services'
      });
    } else {
      statuses.push({
        name: 'GVM/OpenVAS',
        status: 'missing',
        details: 'Credentials not configured',
        icon: Settings,
        category: 'Security Services'
      });
    }

    // Check ZAP configuration
    const zapConfig = config.services.zap;
    if (zapConfig.apiKey && zapConfig.apiKey.length > 0) {
      statuses.push({
        name: 'OWASP ZAP',
        status: 'configured',
        details: 'API key configured',
        icon: Key,
        category: 'Security Services'
      });
    } else {
      statuses.push({
        name: 'OWASP ZAP',
        status: 'missing',
        details: 'API key not configured - required for web app scanning',
        icon: Key,
        category: 'Security Services'
      });
    }

    // Check SpiderFoot configuration
    const spiderfootConfig = config.services.spiderfoot;
    if (spiderfootConfig.apiKey && spiderfootConfig.apiKey.length > 0) {
      statuses.push({
        name: 'SpiderFoot OSINT',
        status: 'configured',
        details: 'API key configured',
        icon: Key,
        category: 'Security Services'
      });
    } else {
      statuses.push({
        name: 'SpiderFoot OSINT',
        status: 'missing',
        details: 'API key not configured - required for OSINT operations',
        icon: Key,
        category: 'Security Services'
      });
    }

    setConfigStatuses(statuses);
    setHasWarnings(statuses.some(s => s.status === 'missing' || s.status === 'partial'));
  };

  const getStatusBadge = (status: ConfigStatus['status']) => {
    switch (status) {
      case 'configured':
        return <Badge className="bg-success text-success-foreground"><CheckCircle className="w-3 h-3 mr-1" />Configured</Badge>;
      case 'partial':
        return <Badge variant="outline" className="bg-warning/10 text-warning border-warning"><AlertCircle className="w-3 h-3 mr-1" />Default</Badge>;
      case 'missing':
        return <Badge variant="destructive"><AlertCircle className="w-3 h-3 mr-1" />Missing</Badge>;
    }
  };

  const groupedConfigs = configStatuses.reduce((acc, config) => {
    if (!acc[config.category]) {
      acc[config.category] = [];
    }
    acc[config.category].push(config);
    return acc;
  }, {} as Record<string, ConfigStatus[]>);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Lock className="w-5 h-5" />
              Environment Configuration Status
            </CardTitle>
            <CardDescription>
              Review and manage service credentials and API keys
            </CardDescription>
          </div>
          {hasWarnings && (
            <Badge variant="destructive" className="text-xs">
              Attention Required
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {hasWarnings && (
          <Alert className="border-warning bg-warning/10">
            <AlertCircle className="h-4 w-4 text-warning" />
            <AlertDescription className="text-warning">
              Some services require configuration. Update credentials in <code className="px-1 py-0.5 rounded bg-muted">src/config/environment.ts</code> for production use.
            </AlertDescription>
          </Alert>
        )}

        {Object.entries(groupedConfigs).map(([category, configs]) => (
          <div key={category} className="space-y-3">
            <h3 className="text-sm font-semibold text-muted-foreground">{category}</h3>
            <div className="space-y-2">
              {configs.map((config) => {
                const Icon = config.icon;
                return (
                  <div
                    key={config.name}
                    className="flex items-center justify-between p-3 rounded-lg border bg-card hover:bg-accent/50 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg ${
                        config.status === 'configured' ? 'bg-success/10 text-success' :
                        config.status === 'partial' ? 'bg-warning/10 text-warning' :
                        'bg-destructive/10 text-destructive'
                      }`}>
                        <Icon className="w-4 h-4" />
                      </div>
                      <div>
                        <p className="font-medium text-sm">{config.name}</p>
                        <p className="text-xs text-muted-foreground">{config.details}</p>
                      </div>
                    </div>
                    {getStatusBadge(config.status)}
                  </div>
                );
              })}
            </div>
          </div>
        ))}

        <div className="pt-4 border-t">
          <p className="text-xs text-muted-foreground">
            💡 <strong>Tip:</strong> For production deployments, store sensitive credentials in secure secret management systems and configure them via environment-specific settings.
          </p>
        </div>
      </CardContent>
    </Card>
  );
};
