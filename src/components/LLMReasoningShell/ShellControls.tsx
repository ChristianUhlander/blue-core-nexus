import { Button } from '@/components/ui/button';
import { 
  Pause, 
  Play, 
  Download, 
  Trash2, 
  Filter,
  Brain,
  Terminal,
  FileText,
  AlertCircle
} from 'lucide-react';
import { ShellFilters } from '@/types/shellTypes';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuCheckboxItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

interface ShellControlsProps {
  isPaused: boolean;
  onTogglePause: () => void;
  onClear: () => void;
  onExport: (format: 'txt' | 'json') => void;
  filters: ShellFilters;
  onFiltersChange: (filters: ShellFilters) => void;
  entryCount: number;
}

export function ShellControls({
  isPaused,
  onTogglePause,
  onClear,
  onExport,
  filters,
  onFiltersChange,
  entryCount,
}: ShellControlsProps) {
  return (
    <div className="flex items-center gap-2 px-3 py-2 border-b border-gray-800 bg-gray-950/90 backdrop-blur">
      <div className="flex items-center gap-1 text-xs text-gray-400">
        <Terminal className="w-3 h-3" />
        <span>{entryCount} entries</span>
      </div>

      <div className="flex-1" />

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button 
            variant="ghost" 
            size="sm" 
            className="h-7 px-2 text-gray-400 hover:text-gray-200"
          >
            <Filter className="w-3.5 h-3.5 mr-1" />
            Filter
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="bg-gray-900 border-gray-800">
          <DropdownMenuCheckboxItem
            checked={filters.showAiThinking}
            onCheckedChange={(checked) => 
              onFiltersChange({ ...filters, showAiThinking: checked })
            }
          >
            <Brain className="w-3.5 h-3.5 mr-2" />
            AI Thinking
          </DropdownMenuCheckboxItem>
          <DropdownMenuCheckboxItem
            checked={filters.showCommands}
            onCheckedChange={(checked) => 
              onFiltersChange({ ...filters, showCommands: checked })
            }
          >
            <Terminal className="w-3.5 h-3.5 mr-2" />
            Commands
          </DropdownMenuCheckboxItem>
          <DropdownMenuCheckboxItem
            checked={filters.showOutput}
            onCheckedChange={(checked) => 
              onFiltersChange({ ...filters, showOutput: checked })
            }
          >
            <FileText className="w-3.5 h-3.5 mr-2" />
            Output
          </DropdownMenuCheckboxItem>
          <DropdownMenuCheckboxItem
            checked={filters.showFindings}
            onCheckedChange={(checked) => 
              onFiltersChange({ ...filters, showFindings: checked })
            }
          >
            <AlertCircle className="w-3.5 h-3.5 mr-2" />
            Findings
          </DropdownMenuCheckboxItem>
          <DropdownMenuCheckboxItem
            checked={filters.showErrors}
            onCheckedChange={(checked) => 
              onFiltersChange({ ...filters, showErrors: checked })
            }
          >
            <AlertCircle className="w-3.5 h-3.5 mr-2" />
            Errors
          </DropdownMenuCheckboxItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Button
        variant="ghost"
        size="sm"
        onClick={onTogglePause}
        className="h-7 px-2 text-gray-400 hover:text-gray-200"
        title={isPaused ? 'Resume' : 'Pause'}
      >
        {isPaused ? (
          <Play className="w-3.5 h-3.5" />
        ) : (
          <Pause className="w-3.5 h-3.5" />
        )}
      </Button>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button 
            variant="ghost" 
            size="sm"
            className="h-7 px-2 text-gray-400 hover:text-gray-200"
          >
            <Download className="w-3.5 h-3.5" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="bg-gray-900 border-gray-800">
          <DropdownMenuCheckboxItem onClick={() => onExport('txt')}>
            Export as TXT
          </DropdownMenuCheckboxItem>
          <DropdownMenuCheckboxItem onClick={() => onExport('json')}>
            Export as JSON
          </DropdownMenuCheckboxItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Button
        variant="ghost"
        size="sm"
        onClick={onClear}
        className="h-7 px-2 text-gray-400 hover:text-red-400"
        title="Clear"
      >
        <Trash2 className="w-3.5 h-3.5" />
      </Button>
    </div>
  );
}
