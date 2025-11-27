import { useLLMShell } from '@/hooks/useLLMShell';
import { ShellControls } from './ShellControls';
import { ShellContent } from './ShellContent';
import { Brain } from 'lucide-react';

interface LLMReasoningShellProps {
  sessionId: string | null;
  enableMockData?: boolean;
}

export function LLMReasoningShell({ sessionId, enableMockData = true }: LLMReasoningShellProps) {
  const {
    entries,
    filters,
    setFilters,
    isPaused,
    togglePause,
    clearEntries,
    exportLog,
    isConnected,
  } = useLLMShell({ sessionId, enableMockData });

  return (
    <div className="flex flex-col h-full bg-gray-950 text-gray-100">
      {/* Header */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-gray-800 bg-gradient-to-r from-gray-900 to-gray-950">
        <Brain className="w-5 h-5 text-cyan-400" />
        <h2 className="text-lg font-bold text-cyan-400">LLM Reasoning Shell</h2>
        {isConnected && (
          <span className="ml-auto text-xs text-green-400 flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            Connected
          </span>
        )}
        {enableMockData && !isConnected && (
          <span className="ml-auto text-xs text-yellow-400 flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-yellow-400" />
            Demo Mode
          </span>
        )}
      </div>

      {/* Controls */}
      <ShellControls
        isPaused={isPaused}
        onTogglePause={togglePause}
        onClear={clearEntries}
        onExport={exportLog}
        filters={filters}
        onFiltersChange={setFilters}
        entryCount={entries.length}
      />

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        <ShellContent entries={entries} isPaused={isPaused} />
      </div>

      {/* Footer hint */}
      {entries.length > 0 && (
        <div className="px-3 py-1 text-xs text-gray-600 border-t border-gray-800 bg-gray-950">
          Click any entry to copy • Scroll up to pause auto-scroll
        </div>
      )}
    </div>
  );
}
