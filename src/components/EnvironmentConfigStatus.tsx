import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { config, logger } from "@/config/environment";
import { CheckCircle2, XCircle, Info, Server, Database, Wifi, Settings } from "lucide-react";
import { Separator } from "@/components/ui/separator";

export const EnvironmentConfigStatus = () => {
  const isProduction = window.location.hostname !== 'localhost';
  const environment = isProduction ? 'Production' : 'Development';

  const ServiceStatus = ({ 
    name, 
    serviceConfig, 
    icon: Icon 
  }: { 
    name: string; 
    serviceConfig: any; 
    icon: any;
  }) => {
    const isConfigured = serviceConfig.baseUrl && serviceConfig.baseUrl !== '';
    
    return (
      <div className="flex items-center justify-between p-4 rounded-lg border border-border/50 bg-card/30 hover:bg-card/50 transition-all duration-200">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10">
            <Icon className="h-5 w-5 text-primary" />
          </div>
          <div>
            <p className="font-medium text-foreground">{name}</p>
            <p className="text-sm text-muted-foreground">{serviceConfig.baseUrl || 'Not configured'}</p>
          </div>
        </div>
        {isConfigured ? (
          <CheckCircle2 className="h-5 w-5 text-green-500" />
        ) : (
          <XCircle className="h-5 w-5 text-destructive" />
        )}
      </div>
    );
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Environment Overview */}
      <Card className="border-primary/20 shadow-lg">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5 text-primary" />
                Environment Configuration
              </CardTitle>
              <CardDescription>Current system configuration and service status</CardDescription>
            </div>
            <Badge variant={isProduction ? "destructive" : "default"} className="text-xs">
              {environment}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* API Configuration */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-muted-foreground" />
              <h3 className="font-semibold text-foreground">API Configuration</h3>
            </div>
            <div className="grid grid-cols-2 gap-4 p-4 rounded-lg bg-muted/30 border border-border/50">
              <div>
                <p className="text-xs text-muted-foreground mb-1">Base URL</p>
                <p className="text-sm font-mono text-foreground">{config.api.baseUrl}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-1">Timeout</p>
                <p className="text-sm font-mono text-foreground">{config.api.timeout}ms</p>
              </div>
            </div>
          </div>

          <Separator />

          {/* Security Services */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Database className="h-4 w-4 text-muted-foreground" />
              <h3 className="font-semibold text-foreground">Security Services</h3>
            </div>
            <div className="grid gap-3">
              <ServiceStatus 
                name="Wazuh SIEM" 
                serviceConfig={config.services.wazuh}
                icon={Server}
              />
              <ServiceStatus 
                name="GVM Scanner" 
                serviceConfig={config.services.gvm}
                icon={Database}
              />
              <ServiceStatus 
                name="ZAP Proxy" 
                serviceConfig={config.services.zap}
                icon={Settings}
              />
            </div>
          </div>

          <Separator />

          {/* WebSocket Configuration */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Wifi className="h-4 w-4 text-muted-foreground" />
              <h3 className="font-semibold text-foreground">WebSocket</h3>
            </div>
            <div className="grid grid-cols-2 gap-4 p-4 rounded-lg bg-muted/30 border border-border/50">
              <div>
                <p className="text-xs text-muted-foreground mb-1">URL</p>
                <p className="text-sm font-mono text-foreground">{config.websocket.url}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-1">Reconnect Interval</p>
                <p className="text-sm font-mono text-foreground">{config.websocket.reconnectInterval}ms</p>
              </div>
            </div>
          </div>

          <Separator />

          {/* Development Settings */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Info className="h-4 w-4 text-muted-foreground" />
              <h3 className="font-semibold text-foreground">Development Settings</h3>
            </div>
            <div className="grid grid-cols-2 gap-4 p-4 rounded-lg bg-muted/30 border border-border/50">
              <div>
                <p className="text-xs text-muted-foreground mb-1">Mock Data</p>
                <Badge variant={config.development.mockData ? "default" : "outline"} className="text-xs">
                  {config.development.mockData ? 'Enabled' : 'Disabled'}
                </Badge>
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-1">Log Level</p>
                <Badge variant="secondary" className="text-xs uppercase">
                  {config.development.logLevel}
                </Badge>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
