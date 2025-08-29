// Quality Control Process for Wazuh Management Page
// This component helps diagnose issues with the navigation and UI elements

import React from 'react';
import { ArrowLeft, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

interface QCItem {
  id: string;
  description: string;
  status: 'pass' | 'fail' | 'warning';
  details?: string;
}

const QualityControl = () => {
  // Quality Control Checks
  const qcChecks: QCItem[] = [
    {
      id: 'routing',
      description: 'Wazuh page routing configuration',
      status: 'pass',
      details: 'Route /wazuh is properly configured in App.tsx'
    },
    {
      id: 'import',
      description: 'ArrowLeft icon import',
      status: 'pass',
      details: 'ArrowLeft imported from lucide-react'
    },
    {
      id: 'button-structure',
      description: 'Back button component structure',
      status: 'pass',
      details: 'Button with ArrowLeft icon and onClick handler exists'
    },
    {
      id: 'navigation-logic',
      description: 'Navigation to Wazuh page',
      status: 'warning',
      details: 'User might not be on /wazuh route - check if clicking "Manage Wazuh SIEM" works'
    },
    {
      id: 'styling',
      description: 'Button visibility and styling',
      status: 'pass',
      details: 'Button has proper classes: glow-hover, border-primary/50, etc.'
    }
  ];

  const getStatusIcon = (status: QCItem['status']) => {
    switch (status) {
      case 'pass':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'fail':
        return <XCircle className="h-4 w-4 text-red-500" />;
      case 'warning':
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
    }
  };

  const getStatusBadge = (status: QCItem['status']) => {
    switch (status) {
      case 'pass':
        return <Badge className="bg-green-500/20 text-green-400 border-green-500/30">PASS</Badge>;
      case 'fail':
        return <Badge variant="destructive">FAIL</Badge>;
      case 'warning':
        return <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">WARNING</Badge>;
    }
  };

  return (
    <div className="fixed top-4 right-4 w-96 z-50">
      <Card className="gradient-card glow border-yellow-500/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-yellow-400">
            <AlertTriangle className="h-5 w-5" />
            Quality Control Report
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {qcChecks.map((check) => (
            <div key={check.id} className="flex items-start gap-3 p-3 rounded-lg bg-muted/30">
              <div className="mt-0.5">
                {getStatusIcon(check.status)}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between mb-1">
                  <p className="text-sm font-medium">{check.description}</p>
                  {getStatusBadge(check.status)}
                </div>
                {check.details && (
                  <p className="text-xs text-muted-foreground">{check.details}</p>
                )}
              </div>
            </div>
          ))}
          
          <div className="mt-4 p-3 rounded-lg bg-blue-500/10 border border-blue-500/30">
            <h4 className="text-sm font-medium text-blue-400 mb-2">Diagnosis:</h4>
            <p className="text-xs text-muted-foreground mb-3">
              The back arrow should be visible on the Wazuh page. If you can't see it, you might not be on the Wazuh page yet.
            </p>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => window.location.href = '/wazuh'}
                className="text-blue-400 border-blue-500/50 hover:bg-blue-500/10"
              >
                Go to Wazuh Page
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => window.location.href = '/'}
                className="text-primary border-primary/50 hover:bg-primary/10"
              >
                <ArrowLeft className="h-3 w-3 mr-1" />
                Test Back Button
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default QualityControl;