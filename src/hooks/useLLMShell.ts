import { useState, useEffect, useCallback, useRef } from 'react';
import { ShellEntry, ShellFilters, defaultShellFilters, ShellEntryType } from '@/types/shellTypes';
import { agenticPentestApi } from '@/services/agenticPentestApi';

interface UseLLMShellOptions {
  sessionId: string | null;
  enableMockData?: boolean;
}

export function useLLMShell({ sessionId, enableMockData = true }: UseLLMShellOptions) {
  const [entries, setEntries] = useState<ShellEntry[]>([]);
  const [filters, setFilters] = useState<ShellFilters>(defaultShellFilters);
  const [isPaused, setIsPaused] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [hasUnreadEntries, setHasUnreadEntries] = useState(false);
  const entriesRef = useRef<ShellEntry[]>([]);
  const maxEntries = 1000;

  const addEntry = useCallback((entry: Omit<ShellEntry, 'id' | 'timestamp'>) => {
    if (isPaused) return;

    const newEntry: ShellEntry = {
      ...entry,
      id: `${Date.now()}-${Math.random()}`,
      timestamp: new Date(),
    };

    setEntries(prev => {
      const updated = [...prev, newEntry];
      if (updated.length > maxEntries) {
        updated.shift(); // Remove oldest entry
      }
      entriesRef.current = updated;
      return updated;
    });

    setHasUnreadEntries(true);
  }, [isPaused]);

  // Mock data generator for testing
  useEffect(() => {
    if (!enableMockData || !sessionId) return;

    const mockScenarios = [
      { type: 'ai_thinking' as ShellEntryType, content: 'Analyzing target scope and attack surface...' },
      { type: 'ai_thinking' as ShellEntryType, content: 'Identified web application on port 443 with TLS 1.2' },
      { type: 'ai_decision' as ShellEntryType, content: 'Starting with passive reconnaissance', metadata: { confidence: 94 } },
      { type: 'command' as ShellEntryType, content: 'nmap -sV -sC -p 443 target.com', metadata: { tool: 'nmap' } },
      { type: 'stdout' as ShellEntryType, content: 'Starting Nmap 7.94 ( https://nmap.org )' },
      { type: 'stdout' as ShellEntryType, content: 'Nmap scan report for target.com (192.168.1.100)' },
      { type: 'stdout' as ShellEntryType, content: 'PORT    STATE SERVICE  VERSION' },
      { type: 'stdout' as ShellEntryType, content: '443/tcp open  https    nginx 1.18.0' },
      { type: 'ai_thinking' as ShellEntryType, content: 'Found nginx 1.18.0 - checking for known CVEs...' },
      { type: 'finding' as ShellEntryType, content: 'Outdated nginx version detected (CVE-2021-23017)', metadata: { severity: 'medium' as const } },
      { type: 'ai_decision' as ShellEntryType, content: 'Next: Run nikto for web vulnerability scanning', metadata: { confidence: 87 } },
      { type: 'command' as ShellEntryType, content: 'nikto -h https://target.com -ssl', metadata: { tool: 'nikto' } },
      { type: 'stdout' as ShellEntryType, content: '- Nikto v2.5.0' },
      { type: 'stdout' as ShellEntryType, content: '+ Target IP:          192.168.1.100' },
      { type: 'stdout' as ShellEntryType, content: '+ Target Hostname:    target.com' },
      { type: 'finding' as ShellEntryType, content: 'Missing security headers: X-Frame-Options, X-Content-Type-Options', metadata: { severity: 'low' as const } },
      { type: 'phase' as ShellEntryType, content: 'Transitioning to active scanning phase', metadata: { phase: 'active_scan' } },
      { type: 'ai_thinking' as ShellEntryType, content: 'Evaluating SQL injection attack vectors on login form...' },
      { type: 'approval' as ShellEntryType, content: 'Requesting approval for SQLMap scan with --risk=2', metadata: { requiresApproval: true } },
    ];

    let index = 0;
    const interval = setInterval(() => {
      if (index < mockScenarios.length) {
        addEntry(mockScenarios[index]);
        index++;
      } else {
        clearInterval(interval);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [sessionId, enableMockData, addEntry]);

  // Real WebSocket integration
  useEffect(() => {
    if (!sessionId || enableMockData) return;

    const handleWebSocketMessage = (event: CustomEvent) => {
      const data = event.detail;

      switch (data.type) {
        case 'ai_reasoning_stream':
          addEntry({ type: 'ai_thinking', content: data.content });
          break;
        case 'ai_decision':
          addEntry({ 
            type: 'ai_decision', 
            content: data.content,
            metadata: { confidence: data.confidence }
          });
          break;
        case 'tool_command':
          addEntry({ 
            type: 'command', 
            content: data.command,
            metadata: { tool: data.tool }
          });
          break;
        case 'tool_output_stream':
          addEntry({ 
            type: data.isError ? 'stderr' : 'stdout', 
            content: data.content 
          });
          break;
        case 'finding_discovered':
          addEntry({ 
            type: 'finding', 
            content: data.description,
            metadata: { severity: data.severity as 'low' | 'medium' | 'high' | 'critical' }
          });
          break;
        case 'phase_transition':
          addEntry({ 
            type: 'phase', 
            content: data.message,
            metadata: { phase: data.phase }
          });
          break;
        case 'approval_request':
          addEntry({ 
            type: 'approval', 
            content: data.message,
            metadata: { requiresApproval: true }
          });
          break;
      }
    };

    window.addEventListener('agenticWebSocketMessage', handleWebSocketMessage as EventListener);
    setIsConnected(true);

    return () => {
      window.removeEventListener('agenticWebSocketMessage', handleWebSocketMessage as EventListener);
      setIsConnected(false);
    };
  }, [sessionId, enableMockData, addEntry]);

  const filteredEntries = entries.filter(entry => {
    switch (entry.type) {
      case 'ai_thinking':
      case 'ai_decision':
        return filters.showAiThinking;
      case 'command':
        return filters.showCommands;
      case 'stdout':
      case 'stderr':
        return filters.showOutput;
      case 'finding':
        return filters.showFindings;
      case 'error':
        return filters.showErrors;
      default:
        return true;
    }
  });

  const togglePause = useCallback(() => {
    setIsPaused(prev => !prev);
  }, []);

  const clearEntries = useCallback(() => {
    setEntries([]);
    entriesRef.current = [];
  }, []);

  const exportLog = useCallback((format: 'txt' | 'json' = 'txt') => {
    const data = format === 'json' 
      ? JSON.stringify(entries, null, 2)
      : entries.map(e => `[${e.timestamp.toISOString()}] [${e.type}] ${e.content}`).join('\n');

    const blob = new Blob([data], { type: format === 'json' ? 'application/json' : 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `llm-shell-${sessionId || 'export'}-${Date.now()}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  }, [entries, sessionId]);

  const markAsRead = useCallback(() => {
    setHasUnreadEntries(false);
  }, []);

  return {
    entries: filteredEntries,
    filters,
    setFilters,
    isPaused,
    togglePause,
    clearEntries,
    exportLog,
    isConnected,
    hasUnreadEntries,
    markAsRead,
  };
}
