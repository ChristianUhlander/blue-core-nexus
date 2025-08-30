import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { toast } from '@/hooks/use-toast';
import { 
  Archive, 
  Search, 
  Save, 
  Clock, 
  ExternalLink,
  Calendar,
  Globe,
  History
} from 'lucide-react';
import { internetArchiveService } from '@/services/internetArchiveService';
import { AvailabilityResponse, CdxRecord } from '@/types/internetArchive';

export const InternetArchiveExplorer: React.FC = () => {
  const [activeTab, setActiveTab] = useState('availability');
  const [loading, setLoading] = useState(false);
  
  // Availability API state
  const [availabilityUrl, setAvailabilityUrl] = useState('');
  const [availabilityTimestamp, setAvailabilityTimestamp] = useState('');
  const [availabilityResult, setAvailabilityResult] = useState<AvailabilityResponse | null>(null);

  // CDX API state
  const [cdxUrl, setCdxUrl] = useState('');
  const [cdxFromDate, setCdxFromDate] = useState('');
  const [cdxToDate, setCdxToDate] = useState('');
  const [cdxMatchType, setCdxMatchType] = useState<'exact' | 'prefix' | 'host' | 'domain'>('exact');
  const [cdxLimit, setCdxLimit] = useState('100');
  const [cdxResults, setCdxResults] = useState<CdxRecord[]>([]);

  // Save Page API state
  const [savePageUrl, setSavePageUrl] = useState('');
  const [captureOptions, setCaptureOptions] = useState({
    capture_outlinks: false,
    capture_screenshot: false
  });

  const handleAvailabilityCheck = async () => {
    if (!availabilityUrl) {
      toast({
        title: "Error",
        description: "Please enter a URL to check",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    try {
      const result = await internetArchiveService.checkAvailability(
        availabilityUrl, 
        availabilityTimestamp || undefined
      );
      setAvailabilityResult(result);
      
      toast({
        title: "Availability Check Complete",
        description: result.archived_snapshots.closest ? 
          "Archived snapshot found!" : 
          "No archived snapshots available",
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to check availability",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCdxSearch = async () => {
    if (!cdxUrl) {
      toast({
        title: "Error", 
        description: "Please enter a URL to search",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    try {
      const results = await internetArchiveService.searchCdx({
        url: cdxUrl,
        from: cdxFromDate || undefined,
        to: cdxToDate || undefined,
        matchType: cdxMatchType,
        limit: parseInt(cdxLimit) || undefined,
        collapse: 'timestamp:8' // Collapse to daily snapshots
      });
      
      setCdxResults(results);
      
      toast({
        title: "CDX Search Complete",
        description: `Found ${results.length} snapshots`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to search CDX database",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSavePage = async () => {
    if (!savePageUrl) {
      toast({
        title: "Error",
        description: "Please enter a URL to save",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    try {
      await internetArchiveService.savePage(savePageUrl, captureOptions);
      
      toast({
        title: "Save Page Request Submitted",
        description: "The page has been queued for archiving",
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to submit save page request",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const openArchivedUrl = (timestamp: string, originalUrl: string) => {
    const archivedUrl = internetArchiveService.getArchivedUrl(originalUrl, timestamp);
    window.open(archivedUrl, '_blank');
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Internet Archive Explorer</h2>
          <p className="text-muted-foreground">
            Access Wayback Machine APIs for web archive research and preservation
          </p>
        </div>
        <Badge variant="outline" className="text-sm">
          <Archive className="w-4 h-4 mr-1" />
          Archive.org APIs
        </Badge>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="availability" className="flex items-center gap-2">
            <Search className="w-4 h-4" />
            Availability
          </TabsTrigger>
          <TabsTrigger value="cdx" className="flex items-center gap-2">
            <History className="w-4 h-4" />
            CDX Search
          </TabsTrigger>
          <TabsTrigger value="save" className="flex items-center gap-2">
            <Save className="w-4 h-4" />
            Save Page
          </TabsTrigger>
          <TabsTrigger value="docs" className="flex items-center gap-2">
            <Globe className="w-4 h-4" />
            API Docs
          </TabsTrigger>
        </TabsList>

        <TabsContent value="availability" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Availability API</CardTitle>
              <CardDescription>
                Check if a URL has archived snapshots, optionally near a specific timestamp
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="availability-url">URL</Label>
                  <Input
                    id="availability-url"
                    value={availabilityUrl}
                    onChange={(e) => setAvailabilityUrl(e.target.value)}
                    placeholder="https://example.com"
                  />
                </div>
                <div>
                  <Label htmlFor="availability-timestamp">Timestamp (optional)</Label>
                  <Input
                    id="availability-timestamp"
                    value={availabilityTimestamp}
                    onChange={(e) => setAvailabilityTimestamp(e.target.value)}
                    placeholder="20230101120000 or YYYY-MM-DD"
                  />
                </div>
              </div>
              
              <Button 
                onClick={handleAvailabilityCheck} 
                disabled={loading}
                className="w-full md:w-auto"
              >
                <Search className="w-4 h-4 mr-2" />
                Check Availability
              </Button>

              {availabilityResult && (
                <div className="mt-4 p-4 border rounded-lg">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-semibold">Availability Result</h4>
                    <Badge variant={availabilityResult.archived_snapshots.closest ? "default" : "secondary"}>
                      {availabilityResult.archived_snapshots.closest ? "Available" : "Not Found"}
                    </Badge>
                  </div>
                  
                  {availabilityResult.archived_snapshots.closest && (
                    <div className="space-y-2 text-sm">
                      <div>
                        <span className="font-medium">Timestamp: </span>
                        {internetArchiveService.formatTimestamp(availabilityResult.archived_snapshots.closest.timestamp)}
                      </div>
                      <div>
                        <span className="font-medium">Status: </span>
                        {availabilityResult.archived_snapshots.closest.status}
                      </div>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => window.open(availabilityResult.archived_snapshots.closest!.url, '_blank')}
                      >
                        <ExternalLink className="w-4 h-4 mr-1" />
                        View Archived Page
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="cdx" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>CDX Server API</CardTitle>
              <CardDescription>
                Search and filter archived snapshots with powerful query options
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div>
                  <Label htmlFor="cdx-url">URL</Label>
                  <Input
                    id="cdx-url"
                    value={cdxUrl}
                    onChange={(e) => setCdxUrl(e.target.value)}
                    placeholder="https://example.com"
                  />
                </div>
                <div>
                  <Label htmlFor="cdx-match-type">Match Type</Label>
                  <Select value={cdxMatchType} onValueChange={(value: any) => setCdxMatchType(value)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="exact">Exact</SelectItem>
                      <SelectItem value="prefix">Prefix</SelectItem>
                      <SelectItem value="host">Host</SelectItem>
                      <SelectItem value="domain">Domain</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label htmlFor="cdx-from">From Date</Label>
                  <Input
                    id="cdx-from"
                    value={cdxFromDate}
                    onChange={(e) => setCdxFromDate(e.target.value)}
                    placeholder="20200101"
                  />
                </div>
                <div>
                  <Label htmlFor="cdx-to">To Date</Label>
                  <Input
                    id="cdx-to"
                    value={cdxToDate}
                    onChange={(e) => setCdxToDate(e.target.value)}
                    placeholder="20231231"
                  />
                </div>
              </div>
              
              <div className="flex items-center gap-4">
                <div>
                  <Label htmlFor="cdx-limit">Limit</Label>
                  <Input
                    id="cdx-limit"
                    value={cdxLimit}
                    onChange={(e) => setCdxLimit(e.target.value)}
                    placeholder="100"
                    className="w-20"
                  />
                </div>
                <Button 
                  onClick={handleCdxSearch} 
                  disabled={loading}
                >
                  <Search className="w-4 h-4 mr-2" />
                  Search CDX
                </Button>
              </div>

              {cdxResults.length > 0 && (
                <div className="mt-4">
                  <h4 className="font-semibold mb-2">Search Results ({cdxResults.length} snapshots)</h4>
                  <div className="max-h-64 overflow-y-auto space-y-2">
                    {cdxResults.map((record, index) => (
                      <div key={index} className="p-3 border rounded-lg text-sm">
                        <div className="flex items-center justify-between">
                          <div>
                            <div className="font-medium">
                              {internetArchiveService.formatTimestamp(record.timestamp)}
                            </div>
                            <div className="text-muted-foreground">
                              Status: {record.statuscode} | Type: {record.mimetype}
                            </div>
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => openArchivedUrl(record.timestamp, record.original)}
                          >
                            <ExternalLink className="w-4 h-4 mr-1" />
                            View
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="save" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Save Page Now API</CardTitle>
              <CardDescription>
                Submit a URL for immediate archiving in the Wayback Machine
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="save-url">URL to Archive</Label>
                <Input
                  id="save-url"
                  value={savePageUrl}
                  onChange={(e) => setSavePageUrl(e.target.value)}
                  placeholder="https://example.com"
                />
              </div>

              <div className="space-y-2">
                <Label>Capture Options</Label>
                <div className="flex items-center space-x-4">
                  <label className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={captureOptions.capture_outlinks}
                      onChange={(e) => setCaptureOptions(prev => ({
                        ...prev,
                        capture_outlinks: e.target.checked
                      }))}
                    />
                    <span className="text-sm">Capture outlinks</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={captureOptions.capture_screenshot}
                      onChange={(e) => setCaptureOptions(prev => ({
                        ...prev,
                        capture_screenshot: e.target.checked
                      }))}
                    />
                    <span className="text-sm">Capture screenshot</span>
                  </label>
                </div>
              </div>

              <Button 
                onClick={handleSavePage} 
                disabled={loading}
                className="w-full md:w-auto"
              >
                <Save className="w-4 h-4 mr-2" />
                Submit for Archiving
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="docs" className="space-y-4">
          <div className="grid gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Search className="w-5 h-5" />
                  Availability API
                </CardTitle>
                <CardDescription>
                  Quick lookup for archived snapshots
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <div><strong>Endpoint:</strong> https://archive.org/wayback/available</div>
                <div><strong>Purpose:</strong> Get the closest archived snapshot for a URL</div>
                <div><strong>Use case:</strong> 404 fallbacks, one-off lookups</div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <History className="w-5 h-5" />
                  CDX Server API
                </CardTitle>
                <CardDescription>
                  Power tool for timeline analysis
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <div><strong>Endpoint:</strong> http://web.archive.org/cdx/search/cdx</div>
                <div><strong>Purpose:</strong> List many snapshots with filtering and pagination</div>
                <div><strong>Use case:</strong> Timeline work, bulk analysis, research</div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Save className="w-5 h-5" />
                  Save Page Now API
                </CardTitle>
                <CardDescription>
                  Archive pages immediately
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <div><strong>Endpoint:</strong> https://web.archive.org/save/</div>
                <div><strong>Purpose:</strong> Tell Wayback to archive a page now</div>
                <div><strong>Use case:</strong> "Fix it in stone" workflows, preservation</div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="w-5 h-5" />
                  Memento API
                </CardTitle>
                <CardDescription>
                  Standards-based time travel
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <div><strong>Endpoint:</strong> http://web.archive.org/timemap/json/</div>
                <div><strong>Purpose:</strong> TimeMap/TimeGate interface</div>
                <div><strong>Use case:</strong> Integration with Memento-compliant tools</div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};