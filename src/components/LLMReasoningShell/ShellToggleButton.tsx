import { Button } from '@/components/ui/button';
import { Terminal } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

interface ShellToggleButtonProps {
  isOpen: boolean;
  onClick: () => void;
  hasNewEntries: boolean;
}

export function ShellToggleButton({ isOpen, onClick, hasNewEntries }: ShellToggleButtonProps) {
  return (
    <Button
      onClick={onClick}
      size="lg"
      className="fixed bottom-6 right-6 z-50 h-14 px-6 rounded-full shadow-2xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white border-2 border-cyan-400/30"
    >
      <Terminal className="w-5 h-5 mr-2" />
      <span className="font-semibold">LLM Shell</span>
      {hasNewEntries && !isOpen && (
        <Badge 
          variant="destructive" 
          className="ml-2 h-5 w-5 p-0 flex items-center justify-center rounded-full animate-pulse"
        >
          •
        </Badge>
      )}
    </Button>
  );
}
