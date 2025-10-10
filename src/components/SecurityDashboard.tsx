import { Shield, FileText, Terminal, Network, Brain, Download, RefreshCw } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { DocumentationLibrary } from "./DocumentationLibrary";
import { IntelligentReportingSystem } from "./IntelligentReportingSystem";
import GVMManagement from "../pages/GVMManagement";
import heroImage from "@/assets/security-hero.jpg";
import { useState } from "react";

/**
 * Streamlined Security Dashboard
 * Focused on: GVM/OpenVAS, AI-Reporting, and Documentation
 */
const SecurityDashboard = () => {
  const { toast } = useToast();
  
  // Dialog states for focused features
  const [isGvmManagementOpen, setIsGvmManagementOpen] = useState(false);
  const [isReportingOpen, setIsReportingOpen] = useState(false);
  const [isDocumentationOpen, setIsDocumentationOpen] = useState(false);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 dark:from-slate-950 dark:via-slate-900 dark:to-slate-800">
      {/* Hero Section */}
      <div className="relative h-[300px] overflow-hidden">
        <img
          src={heroImage}
          alt="Security Operations"
          className="w-full h-full object-cover"
        />
        <div className="absolute inset-0 bg-gradient-to-r from-slate-900/90 to-slate-900/70 flex items-center">
          <div className="container mx-auto px-6">
            <div className="flex items-center gap-4 mb-4">
              <Shield className="h-12 w-12 text-blue-400" />
              <h1 className="text-4xl font-bold text-white">
                Security Operations Center
              </h1>
            </div>
            <p className="text-xl text-slate-300 max-w-2xl">
              Vulnerability Management, Intelligent Reporting & Documentation
            </p>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="container mx-auto px-6 py-8">
        {/* Quick Action Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          {/* GVM/OpenVAS Card */}
          <Card className="hover:shadow-lg transition-shadow cursor-pointer border-2 border-transparent hover:border-primary">
            <CardHeader>
              <div className="flex items-center justify-between">
                <Network className="h-8 w-8 text-primary" />
                <Badge variant="outline">Active</Badge>
              </div>
              <CardTitle className="mt-4">GVM / OpenVAS</CardTitle>
              <CardDescription>
                Vulnerability scanning and management
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button 
                onClick={() => setIsGvmManagementOpen(true)}
                className="w-full"
              >
                <Terminal className="mr-2 h-4 w-4" />
                Launch Console
              </Button>
            </CardContent>
          </Card>

          {/* AI Reporting Card */}
          <Card className="hover:shadow-lg transition-shadow cursor-pointer border-2 border-transparent hover:border-primary">
            <CardHeader>
              <div className="flex items-center justify-between">
                <Brain className="h-8 w-8 text-purple-600" />
                <Badge variant="outline">AI-Powered</Badge>
              </div>
              <CardTitle className="mt-4">Intelligent Reports</CardTitle>
              <CardDescription>
                AI-generated security assessments
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button 
                onClick={() => setIsReportingOpen(true)}
                className="w-full"
                variant="secondary"
              >
                <Download className="mr-2 h-4 w-4" />
                Generate Report
              </Button>
            </CardContent>
          </Card>

          {/* Documentation Card */}
          <Card className="hover:shadow-lg transition-shadow cursor-pointer border-2 border-transparent hover:border-primary">
            <CardHeader>
              <div className="flex items-center justify-between">
                <FileText className="h-8 w-8 text-green-600" />
                <Badge variant="outline">Knowledge Base</Badge>
              </div>
              <CardTitle className="mt-4">Documentation</CardTitle>
              <CardDescription>
                Security guides and references
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button 
                onClick={() => setIsDocumentationOpen(true)}
                className="w-full"
                variant="outline"
              >
                <FileText className="mr-2 h-4 w-4" />
                Browse Docs
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Tabbed Interface */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Security Operations</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  toast({
                    title: "Refreshing...",
                    description: "Updating all security data"
                  });
                }}
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="overview" className="w-full">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="gvm">Vulnerability Scans</TabsTrigger>
                <TabsTrigger value="reports">Reports & Docs</TabsTrigger>
              </TabsList>

              <TabsContent value="overview" className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-lg">System Status</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">GVM Scanner</span>
                          <Badge variant="outline" className="bg-green-50">Ready</Badge>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">AI Reporting</span>
                          <Badge variant="outline" className="bg-green-50">Active</Badge>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-muted-foreground">Documentation</span>
                          <Badge variant="outline" className="bg-green-50">Available</Badge>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle className="text-lg">Quick Actions</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      <Button 
                        variant="outline" 
                        className="w-full justify-start"
                        onClick={() => setIsGvmManagementOpen(true)}
                      >
                        <Network className="mr-2 h-4 w-4" />
                        Start Vulnerability Scan
                      </Button>
                      <Button 
                        variant="outline" 
                        className="w-full justify-start"
                        onClick={() => setIsReportingOpen(true)}
                      >
                        <Brain className="mr-2 h-4 w-4" />
                        Generate Security Report
                      </Button>
                      <Button 
                        variant="outline" 
                        className="w-full justify-start"
                        onClick={() => setIsDocumentationOpen(true)}
                      >
                        <FileText className="mr-2 h-4 w-4" />
                        Search Documentation
                      </Button>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              <TabsContent value="gvm">
                <div className="py-4">
                  <GVMManagement />
                </div>
              </TabsContent>

              <TabsContent value="reports">
                <div className="space-y-4">
                  <Card>
                    <CardHeader>
                      <CardTitle>Reporting & Documentation</CardTitle>
                      <CardDescription>
                        Generate AI-powered reports and access security documentation
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <Button 
                          onClick={() => setIsReportingOpen(true)}
                          className="h-24 flex flex-col items-center justify-center"
                        >
                          <Brain className="h-8 w-8 mb-2" />
                          <span>Generate AI Report</span>
                        </Button>
                        <Button 
                          onClick={() => setIsDocumentationOpen(true)}
                          variant="outline"
                          className="h-24 flex flex-col items-center justify-center"
                        >
                          <FileText className="h-8 w-8 mb-2" />
                          <span>Browse Documentation</span>
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>

      {/* GVM Management Dialog */}
      <Dialog open={isGvmManagementOpen} onOpenChange={setIsGvmManagementOpen}>
        <DialogContent className="max-w-[95vw] max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>GVM / OpenVAS Management</DialogTitle>
            <DialogDescription>
              Vulnerability scanning and management console
            </DialogDescription>
          </DialogHeader>
          <GVMManagement />
        </DialogContent>
      </Dialog>

      {/* AI Reporting Dialog */}
      <Dialog open={isReportingOpen} onOpenChange={setIsReportingOpen}>
        <DialogContent className="max-w-[95vw] max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Intelligent Reporting System</DialogTitle>
            <DialogDescription>
              Generate AI-powered security assessment reports
            </DialogDescription>
          </DialogHeader>
          <IntelligentReportingSystem />
        </DialogContent>
      </Dialog>

      {/* Documentation Dialog */}
      <Dialog open={isDocumentationOpen} onOpenChange={setIsDocumentationOpen}>
        <DialogContent className="max-w-[95vw] max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Security Documentation Library</DialogTitle>
            <DialogDescription>
              Search and browse security guides, techniques, and references
            </DialogDescription>
          </DialogHeader>
          <DocumentationLibrary onClose={() => setIsDocumentationOpen(false)} />
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default SecurityDashboard;
