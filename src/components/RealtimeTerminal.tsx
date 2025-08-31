/**
 * Real-time Terminal Output Component
 * Displays live command execution feedback
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { 
  Terminal, 
  Play, 
  Square, 
  Maximize2, 
  Minimize2, 
  Copy, 
  Download,
  Filter,
  Search,
  CheckCircle,
  AlertTriangle,
  Info,
  Clock,
  Activity
} from "lucide-react";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

export interface TerminalLine {
  id: string;
  timestamp: string;
  type: 'stdout' | 'stderr' | 'system' | 'error' | 'success' | 'info';
  content: string;
  tool?: string;
}

interface RealtimeTerminalProps {
  sessionId?: string;
  isExecuting: boolean;
  onStop?: () => void;
  lines?: TerminalLine[];
  progress?: number;
  currentTool?: string;
}

export const RealtimeTerminal: React.FC<RealtimeTerminalProps> = ({
  sessionId,
  isExecuting,
  onStop,
  lines = [],
  progress = 0,
  currentTool
}) => {
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>(lines);
  const [isMaximized, setIsMaximized] = useState(false);
  const [filter, setFilter] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // Auto-scroll to bottom when new lines arrive
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [terminalLines, autoScroll]);

  // Update lines when props change
  useEffect(() => {
    setTerminalLines(lines);
  }, [lines]);

  // WebSocket connection for real-time updates
  useEffect(() => {
    if (!sessionId) return;

    const ws = new WebSocket(`ws://localhost:8000/ws/terminal/${sessionId}`);
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        if (data.type === 'terminal_output') {
          const newLine: TerminalLine = {
            id: `${Date.now()}-${Math.random()}`,
            timestamp: new Date().toISOString(),
            type: data.output_type || 'stdout',
            content: data.content,
            tool: data.tool
          };
          
          setTerminalLines(prev => [...prev, newLine]);
        }
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error);
      }
    };

    ws.onerror = (error) => {
      console.error('Terminal WebSocket error:', error);
    };

    return () => {
      ws.close();
    };
  }, [sessionId]);

  // Filter lines based on type and search
  const filteredLines = terminalLines.filter(line => {
    const matchesFilter = filter === 'all' || line.type === filter;
    const matchesSearch = !searchTerm || line.content.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  // Get line style based on type
  const getLineStyle = (type: TerminalLine['type']) => {
    switch (type) {
      case 'stderr':
      case 'error':
        return 'text-destructive';
      case 'success':
        return 'text-success';
      case 'info':
        return 'text-info';
      case 'system':
        return 'text-muted-foreground';
      default:
        return 'text-foreground';
    }
  };

  // Get line icon
  const getLineIcon = (type: TerminalLine['type']) => {
    switch (type) {
      case 'error':
        return <AlertTriangle className="h-3 w-3 text-destructive" />;
      case 'success':
        return <CheckCircle className="h-3 w-3 text-success" />;
      case 'info':
      case 'system':
        return <Info className="h-3 w-3 text-info" />;
      default:
        return null;
    }
  };

  // Copy all output
  const copyOutput = useCallback(() => {
    const output = filteredLines.map(line => 
      `[${new Date(line.timestamp).toLocaleTimeString()}] ${line.content}`
    ).join('\n');
    navigator.clipboard.writeText(output);
  }, [filteredLines]);

  // Download output as file
  const downloadOutput = useCallback(() => {
    const output = filteredLines.map(line => 
      `[${line.timestamp}] [${line.type.toUpperCase()}] ${line.content}`
    ).join('\n');
    
    const blob = new Blob([output], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `terminal-output-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [filteredLines]);

  // Clear terminal
  const clearTerminal = useCallback(() => {
    setTerminalLines([]);
  }, []);

  return (
    <Card className={`transition-all duration-300 ${isMaximized ? 'fixed inset-4 z-50' : ''}`}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Terminal className="h-5 w-5" />
              Terminal Output
              {currentTool && (
                <Badge variant="secondary" className="ml-2">
                  {currentTool}
                </Badge>
              )}
            </CardTitle>
            <CardDescription>Real-time command execution feedback</CardDescription>
          </div>
          
          <div className="flex items-center gap-2">
            {/* Progress */}
            {isExecuting && progress > 0 && (
              <div className="flex items-center gap-2 min-w-[100px]">
                <Progress value={progress} className="h-2" />
                <span className="text-xs text-muted-foreground">{progress}%</span>
              </div>
            )}
            
            {/* Controls */}
            <Button size="sm" variant="outline" onClick={copyOutput}>
              <Copy className="h-3 w-3" />
            </Button>
            <Button size="sm" variant="outline" onClick={downloadOutput}>
              <Download className="h-3 w-3" />
            </Button>
            <Button 
              size="sm" 
              variant="outline" 
              onClick={() => setIsMaximized(!isMaximized)}
            >
              {isMaximized ? <Minimize2 className="h-3 w-3" /> : <Maximize2 className="h-3 w-3" />}
            </Button>
            {isExecuting && onStop && (
              <Button size="sm" variant="destructive" onClick={onStop}>
                <Square className="h-3 w-3" />
              </Button>
            )}
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-2 pt-2">
          <div className="flex items-center gap-2 flex-1">
            <Search className="h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search output..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="flex-1"
            />
          </div>
          
          <Select value={filter} onValueChange={setFilter}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="stdout">Output</SelectItem>
              <SelectItem value="stderr">Errors</SelectItem>
              <SelectItem value="success">Success</SelectItem>
              <SelectItem value="info">Info</SelectItem>
              <SelectItem value="system">System</SelectItem>
            </SelectContent>
          </Select>
          
          <Button size="sm" variant="outline" onClick={clearTerminal}>
            Clear
          </Button>
        </div>
      </CardHeader>

      <CardContent className="p-0">
        <ScrollArea 
          className={`${isMaximized ? 'h-[calc(100vh-200px)]' : 'h-96'} font-mono text-sm`}
          ref={scrollRef}
        >
          <div className="p-4 space-y-1">
            {filteredLines.length === 0 ? (
              <div className="text-center text-muted-foreground py-8">
                {isExecuting ? (
                  <div className="flex items-center justify-center gap-2">
                    <Activity className="h-4 w-4 animate-pulse" />
                    Waiting for output...
                  </div>
                ) : (
                  'No output yet. Start a command to see results here.'
                )}
              </div>
            ) : (
              filteredLines.map((line, index) => (
                <div 
                  key={line.id} 
                  className="flex items-start gap-2 hover:bg-muted/50 px-2 py-1 rounded"
                >
                  <span className="text-xs text-muted-foreground mt-0.5 w-20 shrink-0">
                    {new Date(line.timestamp).toLocaleTimeString()}
                  </span>
                  
                  <div className="flex items-center gap-1 mt-0.5">
                    {getLineIcon(line.type)}
                  </div>
                  
                  <span className={`flex-1 break-all ${getLineStyle(line.type)}`}>
                    {line.content}
                  </span>
                  
                  {line.tool && (
                    <Badge variant="outline" className="text-xs shrink-0">
                      {line.tool}
                    </Badge>
                  )}
                </div>
              ))
            )}
            
            {/* Current execution indicator */}
            {isExecuting && (
              <div className="flex items-center gap-2 text-muted-foreground animate-pulse py-2">
                <Activity className="h-3 w-3" />
                <span className="text-xs">Command executing...</span>
              </div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};