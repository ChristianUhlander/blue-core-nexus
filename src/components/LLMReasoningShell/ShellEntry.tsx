import { ShellEntry as ShellEntryType } from '@/types/shellTypes';
import { Brain, Lightbulb, Zap, Search, Target, AlertTriangle, XCircle, Info } from 'lucide-react';
import { useState } from 'react';
import { toast } from 'sonner';

interface ShellEntryProps {
  entry: ShellEntryType;
}

const entryConfig = {
  ai_thinking: {
    icon: Brain,
    color: 'text-cyan-400',
    bg: 'hover:bg-cyan-950/30',
    prefix: '🧠',
  },
  ai_decision: {
    icon: Lightbulb,
    color: 'text-yellow-400',
    bg: 'bg-yellow-950/20 hover:bg-yellow-950/30',
    prefix: '💡',
  },
  command: {
    icon: Zap,
    color: 'text-blue-400',
    bg: 'bg-blue-950/20 hover:bg-blue-950/30',
    prefix: '⚡',
  },
  stdout: {
    icon: null,
    color: 'text-gray-300',
    bg: 'hover:bg-gray-900/30',
    prefix: '│',
  },
  stderr: {
    icon: null,
    color: 'text-red-400',
    bg: 'bg-red-950/20 hover:bg-red-950/30',
    prefix: '│',
  },
  finding: {
    icon: Search,
    color: 'text-orange-400',
    bg: 'bg-orange-950/20 hover:bg-orange-950/30',
    prefix: '🔍',
  },
  phase: {
    icon: Target,
    color: 'text-purple-400',
    bg: 'bg-purple-950/20 hover:bg-purple-950/30',
    prefix: '🎯',
  },
  approval: {
    icon: AlertTriangle,
    color: 'text-amber-400',
    bg: 'bg-amber-950/20 hover:bg-amber-950/30',
    prefix: '⚠️',
  },
  error: {
    icon: XCircle,
    color: 'text-red-500',
    bg: 'bg-red-950/20 hover:bg-red-950/30',
    prefix: '❌',
  },
  info: {
    icon: Info,
    color: 'text-gray-400',
    bg: 'hover:bg-gray-900/30',
    prefix: 'ℹ️',
  },
};

export function ShellEntry({ entry }: ShellEntryProps) {
  const [copied, setCopied] = useState(false);
  const config = entryConfig[entry.type];

  const handleCopy = () => {
    navigator.clipboard.writeText(entry.content);
    setCopied(true);
    toast.success('Copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  };

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    });
  };

  return (
    <div 
      className={`group px-3 py-1.5 font-mono text-sm cursor-pointer transition-colors ${config.bg}`}
      onClick={handleCopy}
      title="Click to copy"
    >
      <div className="flex items-start gap-2">
        <span className="text-gray-500 text-xs select-none shrink-0">
          {formatTime(entry.timestamp)}
        </span>
        <span className={`${config.color} shrink-0 select-none`}>
          {config.prefix}
        </span>
        <div className="flex-1 min-w-0">
          <span className={`${config.color} break-all`}>
            {entry.content}
          </span>
          {entry.metadata?.confidence && (
            <span className="ml-2 text-xs text-gray-500">
              (confidence: {entry.metadata.confidence}%)
            </span>
          )}
          {entry.metadata?.severity && (
            <span className={`ml-2 text-xs uppercase font-bold ${
              entry.metadata.severity === 'critical' ? 'text-red-500' :
              entry.metadata.severity === 'high' ? 'text-orange-500' :
              entry.metadata.severity === 'medium' ? 'text-yellow-500' :
              'text-blue-500'
            }`}>
              [{entry.metadata.severity}]
            </span>
          )}
          {entry.metadata?.tool && (
            <span className="ml-2 text-xs text-gray-600">
              via {entry.metadata.tool}
            </span>
          )}
        </div>
        {copied && (
          <span className="text-xs text-green-400 shrink-0">✓ Copied</span>
        )}
      </div>
    </div>
  );
}
