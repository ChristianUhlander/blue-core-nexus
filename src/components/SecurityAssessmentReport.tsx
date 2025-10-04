import React from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Shield, AlertTriangle, CheckCircle, Clock, TrendingUp, FileText, Download } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface ReportData {
  target: string;
  reportId: string;
  date: string;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  vulnerabilities: {
    high: number;
    medium: number;
    low: number;
  };
  complianceIssues: string[];
  infrastructureFindings: string[];
  webAppFindings: string[];
  siemFindings: string[];
  threatIntel: {
    leakedCredentials: string[];
    suspiciousIPs: string[];
    bruteForceAttempts: number;
  };
  mitreMapping: {
    tactic: string;
    technique: string;
    description: string;
  }[];
  remediationPlan: {
    immediate: string[];
    nearTerm: string[];
    longTerm: string[];
  };
}

interface SecurityAssessmentReportProps {
  data: ReportData;
  audienceType: 'executive' | 'technical' | 'compliance';
}

export const SecurityAssessmentReport: React.FC<SecurityAssessmentReportProps> = ({ data, audienceType }) => {
  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'Critical': return 'destructive';
      case 'High': return 'destructive';
      case 'Medium': return 'default';
      case 'Low': return 'secondary';
      default: return 'default';
    }
  };

  const handleExportPDF = () => {
    window.print();
  };

  return (
    <div className="max-w-6xl mx-auto p-8 bg-background space-y-8 print:p-4">
      {/* Header */}
      <div className="border-b pb-6">
        <div className="flex items-start justify-between mb-4">
          <div>
            <h1 className="text-3xl font-bold mb-2">IPS-STC — Security Assessment Report</h1>
            <div className="flex items-center gap-2 mb-4">
              <Badge variant={getRiskColor(data.riskLevel)} className="text-sm">
                Risk Level: {data.riskLevel}
              </Badge>
              <Badge variant="outline">{audienceType === 'executive' ? 'C-Suite' : audienceType === 'technical' ? 'Technical' : 'Compliance'}</Badge>
            </div>
          </div>
          <Button onClick={handleExportPDF} variant="outline" size="sm" className="print:hidden">
            <Download className="h-4 w-4 mr-2" />
            Export PDF
          </Button>
        </div>
        
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-muted-foreground">Target:</p>
            <p className="font-semibold">{data.target}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Date:</p>
            <p className="font-semibold">{data.date}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Prepared by:</p>
            <p className="font-semibold">IPS-STC</p>
          </div>
          <div>
            <p className="text-muted-foreground">Report ID:</p>
            <p className="font-semibold font-mono text-xs">{data.reportId}</p>
          </div>
        </div>
      </div>

      {/* Executive Summary */}
      <section>
        <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
          <Shield className="h-6 w-6 text-primary" />
          1 — Executive Summary
        </h2>
        <Card>
          <CardContent className="pt-6 space-y-4">
            <div>
              <h3 className="font-semibold mb-2">Risk Classification:</h3>
              <p className="text-sm text-muted-foreground">
                {data.riskLevel} overall risk level detected across infrastructure, applications, and operational environments.
              </p>
            </div>

            <div>
              <h3 className="font-semibold mb-2">Key Outcomes:</h3>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground">
                <li>{data.vulnerabilities.high} high-severity vulnerabilities in infrastructure requiring immediate attention</li>
                <li>{data.vulnerabilities.medium} medium-severity vulnerabilities across web applications and services</li>
                <li>{data.threatIntel.leakedCredentials.length} confirmed credential leaks detected in threat intelligence feeds</li>
                <li>Active brute-force attempts detected: {data.threatIntel.bruteForceAttempts} events in monitoring period</li>
              </ul>
            </div>

            <div>
              <h3 className="font-semibold mb-2">Business Impact:</h3>
              <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4">
                <p className="text-sm text-muted-foreground">
                  If left unaddressed, current exposures may result in:
                </p>
                <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground mt-2">
                  <li>Compromise of customer data and personal records (GDPR exposure)</li>
                  <li>Operational disruption through exploitation of identified vulnerabilities</li>
                  <li>Reputational damage and potential regulatory sanctions</li>
                </ul>
              </div>
            </div>

            <div>
              <h3 className="font-semibold mb-2">Immediate Priorities:</h3>
              <div className="grid gap-2">
                {data.remediationPlan.immediate.map((priority, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-sm">
                    <AlertTriangle className="h-4 w-4 text-destructive mt-0.5 flex-shrink-0" />
                    <span>{priority}</span>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      </section>

      {/* Compliance & Regulatory Risk */}
      <section>
        <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
          <FileText className="h-6 w-6 text-primary" />
          2 — Compliance & Regulatory Risk
        </h2>
        <Card>
          <CardContent className="pt-6 space-y-4">
            <div>
              <h3 className="font-semibold mb-2">Regulatory Exposure:</h3>
              <div className="space-y-2">
                {data.complianceIssues.map((issue, idx) => (
                  <div key={idx} className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3">
                    <p className="text-sm">{issue}</p>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h3 className="font-semibold mb-2">Required Deliverables for Compliance Assurance:</h3>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground">
                <li>A remediation roadmap with assigned owners and deadlines</li>
                <li>Documented evidence of patching, MFA deployment, and credential resets</li>
                <li>An updated incident response procedure addressing identified threats</li>
              </ul>
            </div>
          </CardContent>
        </Card>
      </section>

      {/* Strategic Technical Risk Areas */}
      <section>
        <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
          <TrendingUp className="h-6 w-6 text-primary" />
          3 — Strategic Technical Risk Areas
        </h2>
        
        <div className="space-y-4">
          {/* Infrastructure */}
          <Card>
            <CardContent className="pt-6">
              <h3 className="font-semibold mb-3">3.1 Infrastructure (GVM / OpenVAS)</h3>
              <div className="space-y-2">
                {data.infrastructureFindings.map((finding, idx) => (
                  <div key={idx} className="text-sm bg-muted/50 p-3 rounded-lg">
                    <p>{finding}</p>
                  </div>
                ))}
              </div>
              <div className="mt-3 p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
                <p className="text-sm font-semibold">Business Risk:</p>
                <p className="text-sm text-muted-foreground">
                  These weaknesses can enable adversaries to gain control of management systems critical to operations.
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Web Applications */}
          <Card>
            <CardContent className="pt-6">
              <h3 className="font-semibold mb-3">3.2 Web Applications (OWASP ZAP)</h3>
              <div className="space-y-2">
                {data.webAppFindings.map((finding, idx) => (
                  <div key={idx} className="text-sm bg-muted/50 p-3 rounded-lg">
                    <p>{finding}</p>
                  </div>
                ))}
              </div>
              <div className="mt-3 p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
                <p className="text-sm font-semibold">Business Risk:</p>
                <p className="text-sm text-muted-foreground">
                  Exploitation could enable theft of customer data, disruption of services, and reputational damage.
                </p>
              </div>
            </CardContent>
          </Card>

          {/* SIEM Correlation */}
          <Card>
            <CardContent className="pt-6">
              <h3 className="font-semibold mb-3">3.3 SIEM Correlation (Wazuh) — MITRE ATT&CK Context</h3>
              <div className="space-y-2 mb-4">
                <p className="text-sm font-semibold">Findings:</p>
                {data.siemFindings.map((finding, idx) => (
                  <div key={idx} className="text-sm bg-muted/50 p-3 rounded-lg">
                    <p>{finding}</p>
                  </div>
                ))}
              </div>

              <div className="space-y-2">
                <p className="text-sm font-semibold">Mapped Tactics:</p>
                {data.mitreMapping.map((mapping, idx) => (
                  <div key={idx} className="border rounded-lg p-3">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-semibold text-sm">{mapping.tactic}</span>
                      <Badge variant="outline" className="text-xs">{mapping.technique}</Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">{mapping.description}</p>
                  </div>
                ))}
              </div>

              <div className="mt-3 p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
                <p className="text-sm font-semibold">Business Risk:</p>
                <p className="text-sm text-muted-foreground">
                  Attackers could escalate from account compromise to deeper operational impact, including access to critical infrastructure nodes.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Threat Landscape */}
      <section>
        <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
          <AlertTriangle className="h-6 w-6 text-primary" />
          4 — Threat Landscape & Scenario Analysis
        </h2>
        <Card>
          <CardContent className="pt-6 space-y-4">
            <div>
              <h3 className="font-semibold mb-2">Indicators of Compromise (IoCs):</h3>
              <div className="space-y-2">
                {data.threatIntel.leakedCredentials.length > 0 && (
                  <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-3">
                    <p className="text-sm font-semibold mb-1">Leaked Credentials:</p>
                    <ul className="list-disc list-inside text-sm text-muted-foreground">
                      {data.threatIntel.leakedCredentials.map((cred, idx) => (
                        <li key={idx}>{cred}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {data.threatIntel.suspiciousIPs.length > 0 && (
                  <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-3">
                    <p className="text-sm font-semibold mb-1">Suspicious IP Addresses:</p>
                    <ul className="list-disc list-inside text-sm text-muted-foreground font-mono">
                      {data.threatIntel.suspiciousIPs.map((ip, idx) => (
                        <li key={idx}>{ip}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>

            <div>
              <h3 className="font-semibold mb-2">Worst-Case Scenario:</h3>
              <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4">
                <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
                  <li>Attackers reuse stolen credentials to gain system access</li>
                  <li>Exploit identified vulnerabilities to achieve code execution</li>
                  <li>Move laterally through network infrastructure</li>
                  <li>Gain persistence and control over critical systems</li>
                  <li>Potential for data exfiltration and operational disruption</li>
                </ol>
              </div>
            </div>
          </CardContent>
        </Card>
      </section>

      {/* Remediation Roadmap */}
      <section>
        <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
          <Clock className="h-6 w-6 text-primary" />
          5 — Remediation Roadmap & SLAs
        </h2>
        
        <div className="space-y-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="h-5 w-5 text-destructive" />
                <h3 className="font-semibold">Immediate (0–7 Days)</h3>
              </div>
              <ul className="space-y-2">
                {data.remediationPlan.immediate.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-sm">
                    <CheckCircle className="h-4 w-4 text-destructive mt-0.5 flex-shrink-0" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2 mb-3">
                <Clock className="h-5 w-5 text-amber-500" />
                <h3 className="font-semibold">Near Term (7–30 Days)</h3>
              </div>
              <ul className="space-y-2">
                {data.remediationPlan.nearTerm.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-sm">
                    <CheckCircle className="h-4 w-4 text-amber-500 mt-0.5 flex-shrink-0" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2 mb-3">
                <TrendingUp className="h-5 w-5 text-green-500" />
                <h3 className="font-semibold">Long Term (30–90 Days)</h3>
              </div>
              <ul className="space-y-2">
                {data.remediationPlan.longTerm.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-sm">
                    <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Technical Appendix */}
      {audienceType !== 'executive' && (
        <section>
          <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
            <FileText className="h-6 w-6 text-primary" />
            6 — Technical Appendix
          </h2>
          <Card>
            <CardContent className="pt-6">
              <p className="text-sm text-muted-foreground mb-4">
                This appendix provides technical evidence to substantiate findings and recommendations.
              </p>
              <div className="space-y-3">
                <div className="bg-muted/50 p-3 rounded-lg font-mono text-xs">
                  <p className="font-semibold mb-1">Vulnerability Evidence:</p>
                  <p className="text-muted-foreground">Critical vulnerabilities confirmed via automated scanning</p>
                  <p className="text-muted-foreground">High-severity: {data.vulnerabilities.high} findings</p>
                  <p className="text-muted-foreground">Medium-severity: {data.vulnerabilities.medium} findings</p>
                </div>
                
                {data.threatIntel.leakedCredentials.length > 0 && (
                  <div className="bg-muted/50 p-3 rounded-lg font-mono text-xs">
                    <p className="font-semibold mb-1">Credential Exposure:</p>
                    {data.threatIntel.leakedCredentials.map((cred, idx) => (
                      <p key={idx} className="text-muted-foreground">{cred}</p>
                    ))}
                  </div>
                )}

                <div className="bg-muted/50 p-3 rounded-lg font-mono text-xs">
                  <p className="font-semibold mb-1">SIEM Correlation:</p>
                  <p className="text-muted-foreground">{data.threatIntel.bruteForceAttempts} brute force attempts logged</p>
                  {data.threatIntel.suspiciousIPs.slice(0, 3).map((ip, idx) => (
                    <p key={idx} className="text-muted-foreground">Anomalous activity from {ip}</p>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </section>
      )}

      {/* Footer */}
      <div className="border-t pt-6 text-center text-sm text-muted-foreground">
        <p>This report is confidential and intended solely for the use of {data.target}</p>
        <p className="mt-1">Generated by IPS-STC Security Platform • {data.date}</p>
      </div>
    </div>
  );
};
