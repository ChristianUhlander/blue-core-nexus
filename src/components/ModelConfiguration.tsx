import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Brain, Key, Link, Zap, Settings, Plus, Trash2 } from 'lucide-react';
import { ModelConfiguration as ModelConfig, DEFAULT_MODELS, ModelProvider, ConnectionMethod } from '@/types/modelConfig';
import { useToast } from '@/components/ui/use-toast';

interface ModelConfigurationProps {
  onSave: (models: ModelConfig[]) => void;
  initialModels?: ModelConfig[];
}

export function ModelConfiguration({ onSave, initialModels = [] }: ModelConfigurationProps) {
  const { toast } = useToast();
  const [models, setModels] = useState<ModelConfig[]>(
    initialModels.length > 0
      ? initialModels
      : DEFAULT_MODELS.map((m, i) => ({
          ...m,
          id: `model-${i}`,
          enabled: i === 0, // Enable first model by default
        }))
  );
  
  const [editingModel, setEditingModel] = useState<string | null>(null);

  const addCustomModel = () => {
    const newModel: ModelConfig = {
      id: `model-${Date.now()}`,
      name: 'New Custom Model',
      provider: 'custom',
      connectionMethod: 'api',
      enabled: false,
      apiEndpoint: '',
      customHeaders: {},
    };
    setModels([...models, newModel]);
    setEditingModel(newModel.id);
  };

  const updateModel = (id: string, updates: Partial<ModelConfig>) => {
    setModels(models.map(m => (m.id === id ? { ...m, ...updates } : m)));
  };

  const deleteModel = (id: string) => {
    setModels(models.filter(m => m.id !== id));
    toast({
      title: 'Model Removed',
      description: 'Model configuration has been deleted.',
    });
  };

  const handleSave = () => {
    const enabledModels = models.filter(m => m.enabled);
    if (enabledModels.length === 0) {
      toast({
        title: 'No Models Enabled',
        description: 'Please enable at least one model.',
        variant: 'destructive',
      });
      return;
    }

    onSave(models);
    toast({
      title: 'Configuration Saved',
      description: `${enabledModels.length} model(s) configured successfully.`,
    });
  };

  const testConnection = async (model: ModelConfig) => {
    toast({
      title: 'Testing Connection',
      description: `Testing ${model.name}...`,
    });
    // TODO: Implement actual connection test
    setTimeout(() => {
      toast({
        title: 'Connection Test',
        description: 'Connection test feature coming soon.',
      });
    }, 1000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold flex items-center gap-2">
            <Brain className="w-6 h-6" />
            Model Configuration
          </h2>
          <p className="text-muted-foreground mt-1">
            Configure AI models for automated penetration testing playbooks
          </p>
        </div>
        <Button onClick={addCustomModel} variant="outline">
          <Plus className="w-4 h-4 mr-2" />
          Add Custom Model
        </Button>
      </div>

      <div className="grid gap-4">
        {models.map(model => (
          <Card key={model.id} className={model.enabled ? 'border-primary' : ''}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Switch
                    checked={model.enabled}
                    onCheckedChange={enabled => updateModel(model.id, { enabled })}
                  />
                  <div>
                    <CardTitle className="text-lg">{model.name}</CardTitle>
                    <CardDescription className="flex items-center gap-2 mt-1">
                      <Badge variant="outline" className="capitalize">
                        {model.provider}
                      </Badge>
                      <Badge variant="secondary">
                        {model.connectionMethod === 'api' ? <Key className="w-3 h-3 mr-1" /> : <Link className="w-3 h-3 mr-1" />}
                        {model.connectionMethod}
                      </Badge>
                    </CardDescription>
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setEditingModel(editingModel === model.id ? null : model.id)}
                  >
                    <Settings className="w-4 h-4" />
                  </Button>
                  {model.provider === 'custom' && (
                    <Button variant="ghost" size="sm" onClick={() => deleteModel(model.id)}>
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  )}
                </div>
              </div>
            </CardHeader>

            {editingModel === model.id && (
              <CardContent>
                <Tabs defaultValue="basic" className="w-full">
                  <TabsList className="grid w-full grid-cols-3">
                    <TabsTrigger value="basic">Basic</TabsTrigger>
                    <TabsTrigger value="connection">Connection</TabsTrigger>
                    <TabsTrigger value="advanced">Advanced</TabsTrigger>
                  </TabsList>

                  <TabsContent value="basic" className="space-y-4">
                    <div className="space-y-2">
                      <Label>Model Name</Label>
                      <Input
                        value={model.name}
                        onChange={e => updateModel(model.id, { name: e.target.value })}
                      />
                    </div>

                    <div className="space-y-2">
                      <Label>Provider</Label>
                      <Select
                        value={model.provider}
                        onValueChange={(value: ModelProvider) => updateModel(model.id, { provider: value })}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="openai">OpenAI</SelectItem>
                          <SelectItem value="anthropic">Anthropic</SelectItem>
                          <SelectItem value="custom">Custom Backend</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label>Connection Method</Label>
                      <Select
                        value={model.connectionMethod}
                        onValueChange={(value: ConnectionMethod) =>
                          updateModel(model.id, { connectionMethod: value })
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="api">REST API</SelectItem>
                          <SelectItem value="websocket">WebSocket</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </TabsContent>

                  <TabsContent value="connection" className="space-y-4">
                    {model.connectionMethod === 'api' ? (
                      <>
                        <div className="space-y-2">
                          <Label>API Endpoint</Label>
                          <Input
                            value={model.apiEndpoint || ''}
                            onChange={e => updateModel(model.id, { apiEndpoint: e.target.value })}
                            placeholder="https://api.example.com/v1/chat"
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>API Key</Label>
                          <Input
                            type="password"
                            value={model.apiKey || ''}
                            onChange={e => updateModel(model.id, { apiKey: e.target.value })}
                            placeholder="sk-..."
                          />
                        </div>
                      </>
                    ) : (
                      <div className="space-y-2">
                        <Label>WebSocket Endpoint</Label>
                        <Input
                          value={model.wsEndpoint || ''}
                          onChange={e => updateModel(model.id, { wsEndpoint: e.target.value })}
                          placeholder="wss://api.example.com/v1/realtime"
                        />
                      </div>
                    )}

                    <Button onClick={() => testConnection(model)} variant="outline" className="w-full">
                      <Zap className="w-4 h-4 mr-2" />
                      Test Connection
                    </Button>
                  </TabsContent>

                  <TabsContent value="advanced" className="space-y-4">
                    <div className="space-y-2">
                      <Label>Model Identifier</Label>
                      <Input
                        value={model.model || ''}
                        onChange={e => updateModel(model.id, { model: e.target.value })}
                        placeholder="gpt-4, claude-3-opus, etc."
                      />
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>Temperature</Label>
                        <Input
                          type="number"
                          step="0.1"
                          min="0"
                          max="2"
                          value={model.temperature || 0.7}
                          onChange={e => updateModel(model.id, { temperature: parseFloat(e.target.value) })}
                        />
                      </div>

                      <div className="space-y-2">
                        <Label>Max Tokens</Label>
                        <Input
                          type="number"
                          value={model.maxTokens || 4000}
                          onChange={e => updateModel(model.id, { maxTokens: parseInt(e.target.value) })}
                        />
                      </div>
                    </div>
                  </TabsContent>
                </Tabs>
              </CardContent>
            )}
          </Card>
        ))}
      </div>

      <div className="flex justify-end gap-3">
        <Button variant="outline" onClick={() => setEditingModel(null)}>
          Cancel
        </Button>
        <Button onClick={handleSave}>
          <Settings className="w-4 h-4 mr-2" />
          Save Configuration
        </Button>
      </div>
    </div>
  );
}
