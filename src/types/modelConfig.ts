export type ModelProvider = 'openai' | 'anthropic' | 'custom';
export type ConnectionMethod = 'api' | 'websocket';

export interface ModelConfiguration {
  id: string;
  name: string;
  provider: ModelProvider;
  connectionMethod: ConnectionMethod;
  enabled: boolean;
  
  // API Configuration
  apiKey?: string;
  apiEndpoint?: string;
  
  // WebSocket Configuration
  wsEndpoint?: string;
  
  // Model-specific settings
  model?: string; // e.g., "gpt-4", "claude-3-opus"
  temperature?: number;
  maxTokens?: number;
  
  // Custom backend
  customHeaders?: Record<string, string>;
}

export interface PlaybookModelConfig {
  selectedModelId: string;
  fallbackModelId?: string;
  retryAttempts: number;
  timeout: number;
}

export const DEFAULT_MODELS: Omit<ModelConfiguration, 'id' | 'enabled'>[] = [
  {
    name: 'OpenAI GPT-4',
    provider: 'openai',
    connectionMethod: 'api',
    apiEndpoint: 'https://api.openai.com/v1/chat/completions',
    model: 'gpt-4',
    temperature: 0.7,
    maxTokens: 4000,
  },
  {
    name: 'OpenAI GPT-4 (WebSocket)',
    provider: 'openai',
    connectionMethod: 'websocket',
    wsEndpoint: 'wss://api.openai.com/v1/realtime',
    model: 'gpt-4',
  },
  {
    name: 'Claude 3 Opus',
    provider: 'anthropic',
    connectionMethod: 'api',
    apiEndpoint: 'https://api.anthropic.com/v1/messages',
    model: 'claude-3-opus-20240229',
    temperature: 0.7,
    maxTokens: 4000,
  },
  {
    name: 'Custom Backend',
    provider: 'custom',
    connectionMethod: 'api',
    apiEndpoint: '',
    customHeaders: {},
  },
];
