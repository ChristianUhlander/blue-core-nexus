/**
 * Quality Assurance and Best Effort Module
 * Comprehensive QA framework for penetration testing documentation and compliance
 * 
 * Features:
 * - Pre-engagement checklist
 * - Testing methodology validation
 * - Evidence collection standards
 * - Compliance framework mapping
 * - Report quality assurance
 * - Best effort documentation
 * - Peer review processes
 */

import React, { useState, useCallback, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { 
  CheckCircle, 
  AlertTriangle, 
  FileText, 
  Shield,
  Users,
  Clock,
  Target,
  Eye,
  Settings,
  Download,
  Upload,
  RefreshCw,
  Save,
  Edit,
  Trash2,
  Plus,
  Search,
  Filter,
  BarChart3,
  TrendingUp,
  Award,
  Calendar,
  User,
  Lock,
  Unlock,
  Star,
  Flag,
  MessageSquare,
  BookOpen,
  ExternalLink,
  Lightbulb
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { modernPentestApi } from "@/services/modernPentestApi";
import { QAChecklist, QAItem, ComplianceFramework } from "@/types/modernPentest";

interface QABestEffortModuleProps {
  sessionId?: string;
}

interface QAMetrics {
  totalItems: number;
  completedItems: number;
  criticalItems: number;
  completedCritical: number;
  complianceScore: number;
  qualityScore: number;
}

interface DocumentationTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  template: string;
  required: boolean;
}

export const QABestEffortModule: React.FC<QABestEffortModuleProps> = ({ sessionId }) => {
  const { toast } = useToast();

  // QA State
  const [qaChecklists, setQaChecklists] = useState<QAChecklist[]>([]);
  const [selectedChecklist, setSelectedChecklist] = useState<QAChecklist | null>(null);
  const [qaMetrics, setQaMetrics] = useState<QAMetrics>({
    totalItems: 0,
    completedItems: 0,
    criticalItems: 0,
    completedCritical: 0,
    complianceScore: 0,
    qualityScore: 0
  });

  // Documentation State
  const [documentationItems, setDocumentationItems] = useState<any[]>([]);
  const [selectedTemplate, setSelectedTemplate] = useState<DocumentationTemplate | null>(null);

  // Compliance State
  const [complianceFrameworks, setComplianceFrameworks] = useState<ComplianceFramework[]>([]);

  // Mock QA Checklists
  const mockChecklists: QAChecklist[] = [
    {
      id: 'pre-engagement',
      category: 'preparation',
      items: [
        {
          id: 'scope-defined',
          description: 'Penetration testing scope clearly defined and documented',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'rules-engagement',
          description: 'Rules of engagement signed and approved by all parties',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'emergency-contacts',
          description: 'Emergency contact information documented and verified',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'testing-window',
          description: 'Testing window agreed upon and scheduled',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'tools-approved',
          description: 'Testing tools and techniques approved by client',
          required: true,
          completed: false,
          notes: ''
        }
      ],
      completedItems: 0,
      totalItems: 5,
      compliance: []
    },
    {
      id: 'execution',
      category: 'execution',
      items: [
        {
          id: 'methodology-followed',
          description: 'Established penetration testing methodology followed (OWASP, NIST, PTES)',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'evidence-collected',
          description: 'All security findings properly documented with evidence',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'screenshots-captured',
          description: 'Screenshots and proof-of-concept evidence captured',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'tools-logged',
          description: 'All tool executions and commands logged for audit trail',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'time-tracked',
          description: 'Testing time and phases accurately tracked and documented',
          required: false,
          completed: false,
          notes: ''
        },
        {
          id: 'findings-validated',
          description: 'All findings independently validated and confirmed',
          required: true,
          completed: false,
          notes: ''
        }
      ],
      completedItems: 0,
      totalItems: 6,
      compliance: []
    },
    {
      id: 'reporting',
      category: 'reporting',
      items: [
        {
          id: 'executive-summary',
          description: 'Executive summary written for non-technical stakeholders',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'technical-details',
          description: 'Technical details provided for each finding with remediation steps',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'cvss-scoring',
          description: 'CVSS v3.1 scoring applied to all vulnerabilities',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'remediation-timeline',
          description: 'Remediation timeline and priority levels defined',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'appendices-complete',
          description: 'All technical appendices and supporting documentation included',
          required: false,
          completed: false,
          notes: ''
        },
        {
          id: 'peer-reviewed',
          description: 'Report peer-reviewed by senior penetration tester',
          required: true,
          completed: false,
          notes: ''
        }
      ],
      completedItems: 0,
      totalItems: 6,
      compliance: []
    },
    {
      id: 'cleanup',
      category: 'cleanup',
      items: [
        {
          id: 'artifacts-removed',
          description: 'All testing artifacts and backdoors removed from target systems',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'access-revoked',
          description: 'All temporary access credentials and accounts disabled/removed',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'data-secured',
          description: 'All captured data encrypted and securely stored',
          required: true,
          completed: false,
          notes: ''
        },
        {
          id: 'retention-policy',
          description: 'Data retention policy communicated and implemented',
          required: true,
          completed: false,
          notes: ''
        }
      ],
      completedItems: 0,
      totalItems: 4,
      compliance: []
    }
  ];

  // Documentation Templates
  const documentationTemplates: DocumentationTemplate[] = [
    {
      id: 'exec-summary',
      name: 'Executive Summary',
      description: 'High-level overview for executive stakeholders',
      category: 'reporting',
      required: true,
      template: `# Executive Summary

## Assessment Overview
- **Target:** {target}
- **Assessment Period:** {dates}
- **Testing Method:** {methodology}

## Key Findings
{findings_summary}

## Risk Assessment
{risk_matrix}

## Recommendations
{recommendations}`
    },
    {
      id: 'technical-finding',
      name: 'Technical Finding Template',
      description: 'Detailed technical vulnerability documentation',
      category: 'findings',
      required: true,
      template: `# {finding_title}

## Vulnerability Details
- **Severity:** {severity}
- **CVSS Score:** {cvss_score}
- **Category:** {category}

## Description
{description}

## Technical Details
{technical_details}

## Proof of Concept
{poc_steps}

## Impact
{impact}

## Remediation
{remediation_steps}

## References
{references}`
    },
    {
      id: 'rules-engagement',
      name: 'Rules of Engagement',
      description: 'Legal and procedural guidelines for testing',
      category: 'preparation',
      required: true,
      template: `# Rules of Engagement

## Scope Definition
{scope}

## Testing Constraints
{constraints}

## Emergency Procedures
{emergency_procedures}

## Legal Considerations
{legal_framework}

## Approval Signatures
{signatures}`
    }
  ];

  // Initialize QA data
  useEffect(() => {
    setQaChecklists(mockChecklists);
    setSelectedChecklist(mockChecklists[0]);
    calculateMetrics(mockChecklists);
  }, []);

  // Calculate QA metrics
  const calculateMetrics = useCallback((checklists: QAChecklist[]) => {
    const totalItems = checklists.reduce((acc, list) => acc + list.totalItems, 0);
    const completedItems = checklists.reduce((acc, list) => acc + list.completedItems, 0);
    const criticalItems = checklists.reduce((acc, list) => 
      acc + list.items.filter(item => item.required).length, 0);
    const completedCritical = checklists.reduce((acc, list) => 
      acc + list.items.filter(item => item.required && item.completed).length, 0);

    const complianceScore = totalItems > 0 ? (completedItems / totalItems) * 100 : 0;
    const qualityScore = criticalItems > 0 ? (completedCritical / criticalItems) * 100 : 0;

    setQaMetrics({
      totalItems,
      completedItems,
      criticalItems,
      completedCritical,
      complianceScore: Math.round(complianceScore),
      qualityScore: Math.round(qualityScore)
    });
  }, []);

  // Update QA item
  const updateQAItem = useCallback(async (
    checklistId: string, 
    itemId: string, 
    updates: Partial<QAItem>
  ) => {
    try {
      // Update local state
      setQaChecklists(prev => 
        prev.map(list => {
          if (list.id === checklistId) {
            const updatedItems = list.items.map(item => 
              item.id === itemId ? { ...item, ...updates } : item
            );
            const completedCount = updatedItems.filter(item => item.completed).length;
            
            return {
              ...list,
              items: updatedItems,
              completedItems: completedCount
            };
          }
          return list;
        })
      );

      // Update API if session exists
      if (sessionId) {
        await modernPentestApi.updateQAItem({
          sessionId,
          checklistId,
          itemId,
          completed: updates.completed || false,
          evidence: updates.evidence,
          notes: updates.notes
        });
      }

      // Recalculate metrics
      const updatedChecklists = qaChecklists.map(list => {
        if (list.id === checklistId) {
          const updatedItems = list.items.map(item => 
            item.id === itemId ? { ...item, ...updates } : item
          );
          return {
            ...list,
            items: updatedItems,
            completedItems: updatedItems.filter(item => item.completed).length
          };
        }
        return list;
      });
      
      calculateMetrics(updatedChecklists);

      toast({
        title: "QA Item Updated",
        description: "Quality assurance item has been updated successfully"
      });

    } catch (error) {
      toast({
        title: "Update Failed",
        description: error instanceof Error ? error.message : 'Unknown error occurred',
        variant: "destructive"
      });
    }
  }, [sessionId, qaChecklists, calculateMetrics, toast]);

  // Generate compliance report
  const generateComplianceReport = useCallback(async () => {
    if (!sessionId) {
      toast({
        title: "No Active Session",
        description: "Please start a session to generate compliance report",
        variant: "destructive"
      });
      return;
    }

    try {
      const response = await modernPentestApi.validateCompliance(sessionId);
      
      if (response.success) {
        toast({
          title: "Compliance Report Generated",
          description: "Compliance validation completed successfully"
        });
      }
    } catch (error) {
      toast({
        title: "Report Generation Failed",
        description: error instanceof Error ? error.message : 'Unknown error occurred',
        variant: "destructive"
      });
    }
  }, [sessionId, toast]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-2xl font-bold flex items-center gap-2">
            <CheckCircle className="h-6 w-6" />
            Quality Assurance & Best Effort
          </h3>
          <p className="text-muted-foreground">
            Comprehensive QA framework ensuring testing quality and compliance
          </p>
        </div>
        <div className="flex gap-2">
          <Button onClick={generateComplianceReport} variant="outline">
            <Download className="w-4 h-4 mr-2" />
            Generate Report
          </Button>
          <Badge variant="outline" className="bg-green-50 border-green-200">
            <Award className="w-4 h-4 mr-1" />
            Quality Assured
          </Badge>
        </div>
      </div>

      {/* QA Metrics Dashboard */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">{qaMetrics.completedItems}/{qaMetrics.totalItems}</div>
              <div className="text-sm text-muted-foreground">Items Complete</div>
              <Progress value={(qaMetrics.completedItems / qaMetrics.totalItems) * 100} className="mt-2" />
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-500">{qaMetrics.completedCritical}/{qaMetrics.criticalItems}</div>
              <div className="text-sm text-muted-foreground">Critical Items</div>
              <Progress value={(qaMetrics.completedCritical / qaMetrics.criticalItems) * 100} className="mt-2" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-500">{qaMetrics.complianceScore}%</div>
              <div className="text-sm text-muted-foreground">Compliance Score</div>
              <Progress value={qaMetrics.complianceScore} className="mt-2" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-500">{qaMetrics.qualityScore}%</div>
              <div className="text-sm text-muted-foreground">Quality Score</div>
              <Progress value={qaMetrics.qualityScore} className="mt-2" />
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="checklists" className="w-full">
        <TabsList className="grid grid-cols-5 w-full">
          <TabsTrigger value="checklists">QA Checklists</TabsTrigger>
          <TabsTrigger value="documentation">Documentation</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
          <TabsTrigger value="metrics">Metrics</TabsTrigger>
        </TabsList>

        {/* QA Checklists Tab */}
        <TabsContent value="checklists" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Checklist Categories */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileText className="h-5 w-5" />
                  QA Categories
                </CardTitle>
                <CardDescription>
                  Quality assurance checklists by category
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {qaChecklists.map((checklist) => (
                  <Card 
                    key={checklist.id}
                    className={`cursor-pointer transition-all ${
                      selectedChecklist?.id === checklist.id 
                        ? 'border-primary bg-primary/5' 
                        : 'hover:border-primary/50'
                    }`}
                    onClick={() => setSelectedChecklist(checklist)}
                  >
                    <CardContent className="pt-4">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-semibold text-sm capitalize">{checklist.category}</h4>
                        <Badge variant="outline">
                          {checklist.completedItems}/{checklist.totalItems}
                        </Badge>
                      </div>
                      <Progress 
                        value={(checklist.completedItems / checklist.totalItems) * 100} 
                        className="h-2" 
                      />
                      <div className="text-xs text-muted-foreground mt-1">
                        {Math.round((checklist.completedItems / checklist.totalItems) * 100)}% complete
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </CardContent>
            </Card>

            {/* Selected Checklist Items */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Target className="h-5 w-5" />
                  {selectedChecklist ? `${selectedChecklist.category} Checklist` : 'Select Checklist'}
                </CardTitle>
                <CardDescription>
                  Quality assurance items for selected category
                </CardDescription>
              </CardHeader>
              <CardContent>
                {selectedChecklist ? (
                  <ScrollArea className="h-96">
                    <div className="space-y-4">
                      {selectedChecklist.items.map((item) => (
                        <Card key={item.id} className="border-l-4 border-l-blue-500">
                          <CardContent className="pt-4">
                            <div className="space-y-3">
                              <div className="flex items-start gap-3">
                                <Checkbox
                                  checked={item.completed}
                                  onCheckedChange={(checked) => 
                                    updateQAItem(selectedChecklist.id, item.id, { 
                                      completed: checked as boolean 
                                    })
                                  }
                                />
                                <div className="flex-1">
                                  <div className="flex items-center gap-2 mb-1">
                                    <p className="text-sm font-medium">{item.description}</p>
                                    {item.required && (
                                      <Badge variant="destructive" className="text-xs">
                                        Required
                                      </Badge>
                                    )}
                                  </div>
                                  
                                  <Textarea
                                    placeholder="Add notes or evidence..."
                                    value={item.notes || ''}
                                    onChange={(e) => 
                                      updateQAItem(selectedChecklist.id, item.id, { 
                                        notes: e.target.value 
                                      })
                                    }
                                    className="text-xs mt-2"
                                    rows={2}
                                  />
                                  
                                  {item.reviewer && (
                                    <div className="text-xs text-muted-foreground mt-1">
                                      Reviewed by: {item.reviewer} on {item.reviewDate}
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </ScrollArea>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <CheckCircle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>Select a checklist category to view items</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Documentation Tab */}
        <TabsContent value="documentation" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <BookOpen className="h-5 w-5" />
                Documentation Standards
              </CardTitle>
              <CardDescription>
                Ensure comprehensive and standardized documentation
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {documentationTemplates.map((template) => (
                  <Card key={template.id} className="cursor-pointer hover:shadow-md transition-shadow">
                    <CardContent className="pt-6">
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <h4 className="font-semibold text-sm">{template.name}</h4>
                          {template.required && (
                            <Badge variant="destructive" className="text-xs">
                              Required
                            </Badge>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground">{template.description}</p>
                        <Button size="sm" className="w-full" variant="outline">
                          <Edit className="w-3 h-3 mr-1" />
                          Use Template
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Compliance Tab */}
        <TabsContent value="compliance" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Compliance Frameworks */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Compliance Frameworks
                </CardTitle>
                <CardDescription>
                  Industry standards and regulatory compliance
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {[
                    { name: 'ISO 27001:2013', status: 'compliant', progress: 95 },
                    { name: 'NIST Cybersecurity Framework', status: 'partial', progress: 78 },
                    { name: 'OWASP Testing Guide v4', status: 'compliant', progress: 90 },
                    { name: 'PTES (Penetration Testing Execution Standard)', status: 'compliant', progress: 88 },
                    { name: 'PCI DSS v3.2.1', status: 'pending', progress: 45 }
                  ].map((framework) => (
                    <Card key={framework.name} className="p-4">
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <h5 className="font-medium text-sm">{framework.name}</h5>
                          <Badge 
                            variant={
                              framework.status === 'compliant' ? 'default' :
                              framework.status === 'partial' ? 'secondary' : 'outline'
                            }
                          >
                            {framework.status}
                          </Badge>
                        </div>
                        <Progress value={framework.progress} className="h-2" />
                        <div className="text-xs text-muted-foreground">
                          {framework.progress}% compliance
                        </div>
                      </div>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Compliance Actions */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Flag className="h-5 w-5" />
                  Compliance Actions
                </CardTitle>
                <CardDescription>
                  Required actions for full compliance
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {[
                    {
                      action: 'Complete PCI DSS scope documentation',
                      priority: 'high',
                      framework: 'PCI DSS',
                      dueDate: '2024-02-15'
                    },
                    {
                      action: 'Update NIST framework risk assessment',
                      priority: 'medium',
                      framework: 'NIST',
                      dueDate: '2024-02-20'
                    },
                    {
                      action: 'Review ISO 27001 control implementation',
                      priority: 'low',
                      framework: 'ISO 27001',
                      dueDate: '2024-03-01'
                    }
                  ].map((action, index) => (
                    <Card key={index} className="p-3">
                      <div className="space-y-2">
                        <div className="flex items-start justify-between">
                          <p className="text-sm font-medium">{action.action}</p>
                          <Badge 
                            variant={
                              action.priority === 'high' ? 'destructive' :
                              action.priority === 'medium' ? 'secondary' : 'outline'
                            }
                            className="text-xs"
                          >
                            {action.priority}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                          <Badge variant="outline" className="text-xs">
                            {action.framework}
                          </Badge>
                          <Calendar className="w-3 h-3" />
                          Due: {action.dueDate}
                        </div>
                      </div>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Templates Tab */}
        <TabsContent value="templates" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Template Library */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileText className="h-5 w-5" />
                  Template Library
                </CardTitle>
                <CardDescription>
                  Standardized templates for consistent documentation
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {documentationTemplates.map((template) => (
                    <Card 
                      key={template.id}
                      className={`cursor-pointer transition-all ${
                        selectedTemplate?.id === template.id 
                          ? 'border-primary bg-primary/5' 
                          : 'hover:border-primary/50'
                      }`}
                      onClick={() => setSelectedTemplate(template)}
                    >
                      <CardContent className="pt-4">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-semibold text-sm">{template.name}</h4>
                          <div className="flex gap-1">
                            {template.required && (
                              <Badge variant="destructive" className="text-xs">
                                Required
                              </Badge>
                            )}
                            <Badge variant="outline" className="text-xs">
                              {template.category}
                            </Badge>
                          </div>
                        </div>
                        <p className="text-xs text-muted-foreground">{template.description}</p>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Template Preview */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Eye className="h-5 w-5" />
                  Template Preview
                </CardTitle>
                <CardDescription>
                  Preview and customize selected template
                </CardDescription>
              </CardHeader>
              <CardContent>
                {selectedTemplate ? (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h4 className="font-semibold">{selectedTemplate.name}</h4>
                      <div className="flex gap-2">
                        <Button size="sm" variant="outline">
                          <Download className="w-3 h-3 mr-1" />
                          Export
                        </Button>
                        <Button size="sm">
                          <Edit className="w-3 h-3 mr-1" />
                          Customize
                        </Button>
                      </div>
                    </div>
                    
                    <ScrollArea className="h-64">
                      <pre className="text-xs bg-gray-50 dark:bg-gray-900 p-3 rounded border">
                        {selectedTemplate.template}
                      </pre>
                    </ScrollArea>
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>Select a template to preview</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Metrics Tab */}
        <TabsContent value="metrics" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Quality Metrics */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <BarChart3 className="h-5 w-5" />
                  Quality Metrics
                </CardTitle>
                <CardDescription>
                  Assessment quality and completeness metrics
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {[
                    { metric: 'Documentation Completeness', value: qaMetrics.complianceScore, target: 95 },
                    { metric: 'Critical Items Completion', value: qaMetrics.qualityScore, target: 100 },
                    { metric: 'Evidence Quality Score', value: 87, target: 90 },
                    { metric: 'Peer Review Coverage', value: 92, target: 100 }
                  ].map((metric) => (
                    <div key={metric.metric} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium">{metric.metric}</span>
                        <span className="text-sm text-muted-foreground">
                          {metric.value}% / {metric.target}%
                        </span>
                      </div>
                      <Progress value={metric.value} className="h-2" />
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Improvement Recommendations */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <TrendingUp className="h-5 w-5" />
                  Improvement Recommendations
                </CardTitle>
                <CardDescription>
                  Actionable suggestions for quality improvement
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {[
                    {
                      recommendation: 'Complete all critical QA checklist items before proceeding',
                      priority: 'high',
                      impact: 'Quality assurance'
                    },
                    {
                      recommendation: 'Add peer review process for all high-severity findings',
                      priority: 'medium',
                      impact: 'Finding validation'
                    },
                    {
                      recommendation: 'Implement automated compliance checking',
                      priority: 'low',
                      impact: 'Process efficiency'
                    }
                  ].map((rec, index) => (
                    <Alert key={index}>
                      <Lightbulb className="h-4 w-4" />
                      <AlertDescription>
                        <div className="space-y-1">
                          <p className="text-sm font-medium">{rec.recommendation}</p>
                          <div className="flex gap-2">
                            <Badge 
                              variant={
                                rec.priority === 'high' ? 'destructive' :
                                rec.priority === 'medium' ? 'secondary' : 'outline'
                              }
                              className="text-xs"
                            >
                              {rec.priority}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              Impact: {rec.impact}
                            </span>
                          </div>
                        </div>
                      </AlertDescription>
                    </Alert>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};