import { ModelConfiguration, ConnectionMethod } from '@/types/modelConfig';

export interface AIMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface AIResponse {
  content: string;
  model: string;
  usage?: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
}

export class ModelService {
  private model: ModelConfiguration;
  private ws: WebSocket | null = null;

  constructor(model: ModelConfiguration) {
    this.model = model;
  }

  async sendMessage(messages: AIMessage[]): Promise<AIResponse> {
    if (this.model.connectionMethod === 'api') {
      return this.sendAPIMessage(messages);
    } else {
      return this.sendWebSocketMessage(messages);
    }
  }

  private async sendAPIMessage(messages: AIMessage[]): Promise<AIResponse> {
    if (!this.model.apiEndpoint) {
      throw new Error('API endpoint not configured');
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...this.model.customHeaders,
    };

    if (this.model.apiKey) {
      if (this.model.provider === 'anthropic') {
        headers['x-api-key'] = this.model.apiKey;
        headers['anthropic-version'] = '2023-06-01';
      } else {
        headers['Authorization'] = `Bearer ${this.model.apiKey}`;
      }
    }

    let body: any;
    
    if (this.model.provider === 'anthropic') {
      body = {
        model: this.model.model || 'claude-3-opus-20240229',
        messages: messages.filter(m => m.role !== 'system'),
        system: messages.find(m => m.role === 'system')?.content,
        max_tokens: this.model.maxTokens || 4000,
        temperature: this.model.temperature || 0.7,
      };
    } else {
      body = {
        model: this.model.model || 'gpt-4',
        messages,
        temperature: this.model.temperature || 0.7,
        max_tokens: this.model.maxTokens || 4000,
      };
    }

    const response = await fetch(this.model.apiEndpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`API request failed: ${response.status} - ${errorText}`);
    }

    const data = await response.json();

    if (this.model.provider === 'anthropic') {
      return {
        content: data.content[0].text,
        model: data.model,
        usage: {
          promptTokens: data.usage.input_tokens,
          completionTokens: data.usage.output_tokens,
          totalTokens: data.usage.input_tokens + data.usage.output_tokens,
        },
      };
    } else {
      return {
        content: data.choices[0].message.content,
        model: data.model,
        usage: {
          promptTokens: data.usage.prompt_tokens,
          completionTokens: data.usage.completion_tokens,
          totalTokens: data.usage.total_tokens,
        },
      };
    }
  }

  private async sendWebSocketMessage(messages: AIMessage[]): Promise<AIResponse> {
    return new Promise((resolve, reject) => {
      if (!this.model.wsEndpoint) {
        reject(new Error('WebSocket endpoint not configured'));
        return;
      }

      this.ws = new WebSocket(this.model.wsEndpoint);
      
      let responseContent = '';

      this.ws.onopen = () => {
        const payload = {
          model: this.model.model,
          messages,
          temperature: this.model.temperature || 0.7,
          max_tokens: this.model.maxTokens || 4000,
        };
        this.ws!.send(JSON.stringify(payload));
      };

      this.ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === 'content_delta') {
          responseContent += data.delta;
        } else if (data.type === 'message_complete') {
          resolve({
            content: responseContent,
            model: this.model.model || 'unknown',
          });
          this.ws!.close();
        } else if (data.type === 'error') {
          reject(new Error(data.message));
          this.ws!.close();
        }
      };

      this.ws.onerror = (error) => {
        reject(new Error('WebSocket connection error'));
        this.ws!.close();
      };

      setTimeout(() => {
        if (this.ws && this.ws.readyState !== WebSocket.CLOSED) {
          this.ws.close();
          reject(new Error('WebSocket timeout'));
        }
      }, 30000);
    });
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}

export function createModelService(model: ModelConfiguration): ModelService {
  return new ModelService(model);
}
