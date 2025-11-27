import { useEffect, useRef } from 'react';
import { ShellEntry as ShellEntryType } from '@/types/shellTypes';
import { ShellEntry } from './ShellEntry';
import { ScrollArea } from '@/components/ui/scroll-area';

interface ShellContentProps {
  entries: ShellEntryType[];
  isPaused: boolean;
}

export function ShellContent({ entries, isPaused }: ShellContentProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const shouldAutoScroll = useRef(true);

  useEffect(() => {
    if (shouldAutoScroll.current && !isPaused && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [entries, isPaused]);

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    const target = e.target as HTMLDivElement;
    const isAtBottom = Math.abs(
      target.scrollHeight - target.scrollTop - target.clientHeight
    ) < 10;
    shouldAutoScroll.current = isAtBottom;
  };

  if (entries.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500 text-sm">
        <div className="text-center">
          <div className="text-4xl mb-2">🤖</div>
          <div>Waiting for LLM activity...</div>
          <div className="text-xs mt-1 text-gray-600">
            Shell will display AI reasoning, commands, and outputs here
          </div>
        </div>
      </div>
    );
  }

  return (
    <ScrollArea className="h-full">
      <div 
        ref={scrollRef}
        onScroll={handleScroll}
        className="h-full overflow-y-auto"
      >
        {entries.map((entry) => (
          <ShellEntry key={entry.id} entry={entry} />
        ))}
        <div className="h-4" /> {/* Bottom padding */}
      </div>
    </ScrollArea>
  );
}
