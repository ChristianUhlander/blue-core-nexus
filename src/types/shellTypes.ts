export type ShellEntryType = 
  | 'ai_thinking'      // LLM reasoning/chain of thought
  | 'ai_decision'      // Decision made by AI with confidence
  | 'command'          // Command being executed
  | 'stdout'           // Tool standard output
  | 'stderr'           // Tool error output  
  | 'finding'          // Security finding discovered
  | 'phase'            // Phase transition
  | 'approval'         // Approval request
  | 'error'            // System error
  | 'info';            // General info

export interface ShellEntry {
  id: string;
  timestamp: Date;
  type: ShellEntryType;
  content: string;
  metadata?: {
    tool?: string;
    confidence?: number;
    severity?: 'low' | 'medium' | 'high' | 'critical';
    command?: string;
    phase?: string;
    requiresApproval?: boolean;
  };
}

export interface ShellFilters {
  showAiThinking: boolean;
  showCommands: boolean;
  showOutput: boolean;
  showFindings: boolean;
  showErrors: boolean;
}

export const defaultShellFilters: ShellFilters = {
  showAiThinking: true,
  showCommands: true,
  showOutput: true,
  showFindings: true,
  showErrors: true,
};
