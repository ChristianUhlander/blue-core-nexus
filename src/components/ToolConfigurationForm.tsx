/**
 * Tool Configuration Form Component
 * Provides simple flag selection and custom input for CLI tools
 */

import React, { useState, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { 
  Settings, 
  Terminal, 
  Zap, 
  Play, 
  Info, 
  AlertTriangle,
  CheckCircle,
  Copy,
  Save,
  RotateCcw
} from "lucide-react";

export interface ToolFlag {
  flag: string;
  description: string;
  category: 'basic' | 'advanced' | 'output' | 'timing' | 'evasion';
  type: 'boolean' | 'string' | 'number';
  defaultValue?: any;
  examples?: string[];
  conflicts?: string[];
  requires?: string[];
}

export interface ToolConfig {
  name: string;
  description: string;
  category: 'network' | 'web' | 'ad' | 'kubernetes' | 'osint';
  commonFlags: ToolFlag[];
  automationCapable: boolean;
  automationDescription?: string;
  examples: {
    basic: string;
    intermediate: string;
    advanced: string;
  };
}

interface ToolConfigurationFormProps {
  tool: ToolConfig;
  onConfigurationChange: (config: { flags: Record<string, any>, customArgs: string, command: string }) => void;
  onExecute?: () => void;
  isExecuting?: boolean;
}

export const ToolConfigurationForm: React.FC<ToolConfigurationFormProps> = ({
  tool,
  onConfigurationChange,
  onExecute,
  isExecuting = false
}) => {
  const [selectedFlags, setSelectedFlags] = useState<Record<string, any>>({});
  const [customArgs, setCustomArgs] = useState('');
  const [activeTab, setActiveTab] = useState('basic');
  const [generatedCommand, setGeneratedCommand] = useState('');

  // Generate command based on selected flags and custom args
  const generateCommand = useCallback(() => {
    const flagStrings: string[] = [];
    
    Object.entries(selectedFlags).forEach(([flag, value]) => {
      if (value === true) {
        flagStrings.push(flag);
      } else if (value && value !== false && value !== '') {
        if (typeof value === 'string' && value.includes(' ')) {
          flagStrings.push(`${flag} "${value}"`);
        } else {
          flagStrings.push(`${flag} ${value}`);
        }
      }
    });

    const command = `${tool.name.toLowerCase()} ${flagStrings.join(' ')} ${customArgs}`.trim();
    setGeneratedCommand(command);
    
    onConfigurationChange({
      flags: selectedFlags,
      customArgs,
      command
    });
    
    return command;
  }, [selectedFlags, customArgs, tool.name, onConfigurationChange]);

  // Update flag value
  const updateFlag = useCallback((flag: string, value: any) => {
    setSelectedFlags(prev => {
      const newFlags = { ...prev };
      
      if (value === false || value === '' || value === null) {
        delete newFlags[flag];
      } else {
        newFlags[flag] = value;
      }
      
      return newFlags;
    });
  }, []);

  // Copy command to clipboard
  const copyCommand = useCallback(() => {
    navigator.clipboard.writeText(generatedCommand);
  }, [generatedCommand]);

  // Reset configuration
  const resetConfig = useCallback(() => {
    setSelectedFlags({});
    setCustomArgs('');
    setGeneratedCommand('');
  }, []);

  // Filter flags by category
  const getFilteredFlags = (category: string) => {
    return tool.commonFlags.filter(flag => flag.category === category);
  };

  // Check if flag has conflicts
  const hasConflicts = (flag: ToolFlag) => {
    if (!flag.conflicts) return false;
    return flag.conflicts.some(conflict => selectedFlags[conflict] !== undefined);
  };

  // Check if flag requirements are met
  const requirementsMet = (flag: ToolFlag) => {
    if (!flag.requires) return true;
    return flag.requires.every(requirement => selectedFlags[requirement] !== undefined);
  };

  React.useEffect(() => {
    generateCommand();
  }, [generateCommand]);

  const renderFlagInput = (flag: ToolFlag) => {
    const isDisabled = hasConflicts(flag) || !requirementsMet(flag);
    const currentValue = selectedFlags[flag.flag];

    switch (flag.type) {
      case 'boolean':
        return (
          <div className="flex items-center space-x-2">
            <Checkbox
              id={flag.flag}
              checked={currentValue === true}
              onCheckedChange={(checked) => updateFlag(flag.flag, checked)}
              disabled={isDisabled}
            />
            <Label 
              htmlFor={flag.flag} 
              className={`text-sm ${isDisabled ? 'text-muted-foreground' : ''}`}
            >
              {flag.flag}
            </Label>
          </div>
        );
      
      case 'string':
        return (
          <div className="space-y-2">
            <Label htmlFor={flag.flag} className="text-sm font-medium">
              {flag.flag}
            </Label>
            <Input
              id={flag.flag}
              value={currentValue || ''}
              onChange={(e) => updateFlag(flag.flag, e.target.value)}
              placeholder={flag.examples?.[0] || 'Enter value...'}
              disabled={isDisabled}
              className="text-sm"
            />
            {flag.examples && (
              <div className="flex flex-wrap gap-1">
                {flag.examples.map((example, idx) => (
                  <Badge 
                    key={idx}
                    variant="outline" 
                    className="text-xs cursor-pointer hover:bg-secondary"
                    onClick={() => !isDisabled && updateFlag(flag.flag, example)}
                  >
                    {example}
                  </Badge>
                ))}
              </div>
            )}
          </div>
        );
      
      case 'number':
        return (
          <div className="space-y-2">
            <Label htmlFor={flag.flag} className="text-sm font-medium">
              {flag.flag}
            </Label>
            <Input
              id={flag.flag}
              type="number"
              value={currentValue || ''}
              onChange={(e) => updateFlag(flag.flag, e.target.value)}
              placeholder={flag.defaultValue?.toString() || '0'}
              disabled={isDisabled}
              className="text-sm"
            />
          </div>
        );
      
      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      {/* Tool Header */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            {tool.name} Configuration
          </CardTitle>
          <CardDescription>{tool.description}</CardDescription>
          
          {tool.automationCapable && (
            <Alert>
              <Zap className="h-4 w-4" />
              <AlertDescription>
                <strong>Automation Available:</strong> {tool.automationDescription}
              </AlertDescription>
            </Alert>
          )}
        </CardHeader>
      </Card>

      {/* Configuration Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid grid-cols-4 w-full">
          <TabsTrigger value="basic">Basic</TabsTrigger>
          <TabsTrigger value="advanced">Advanced</TabsTrigger>
          <TabsTrigger value="examples">Examples</TabsTrigger>
          <TabsTrigger value="command">Command</TabsTrigger>
        </TabsList>

        {/* Basic Configuration */}
        <TabsContent value="basic" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Common Options</CardTitle>
              <CardDescription>
                Most frequently used flags for {tool.name}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {getFilteredFlags('basic').map((flag) => (
                <div key={flag.flag} className="space-y-2">
                  <div className="flex items-start justify-between">
                    <div className="flex-1 space-y-2">
                      {renderFlagInput(flag)}
                      <p className="text-xs text-muted-foreground">{flag.description}</p>
                      
                      {hasConflicts(flag) && (
                        <div className="flex items-center gap-1 text-xs text-destructive">
                          <AlertTriangle className="h-3 w-3" />
                          Conflicts with: {flag.conflicts?.join(', ')}
                        </div>
                      )}
                      
                      {flag.requires && !requirementsMet(flag) && (
                        <div className="flex items-center gap-1 text-xs text-warning">
                          <Info className="h-3 w-3" />
                          Requires: {flag.requires.join(', ')}
                        </div>
                      )}
                    </div>
                  </div>
                  <Separator />
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Advanced Configuration */}
        <TabsContent value="advanced" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Advanced Flags */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Advanced Options</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {getFilteredFlags('advanced').concat(getFilteredFlags('evasion')).map((flag) => (
                  <div key={flag.flag} className="space-y-2">
                    {renderFlagInput(flag)}
                    <p className="text-xs text-muted-foreground">{flag.description}</p>
                    <Separator />
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Timing & Output */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Timing & Output</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {getFilteredFlags('timing').concat(getFilteredFlags('output')).map((flag) => (
                  <div key={flag.flag} className="space-y-2">
                    {renderFlagInput(flag)}
                    <p className="text-xs text-muted-foreground">{flag.description}</p>
                    <Separator />
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {/* Custom Arguments */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Custom Arguments</CardTitle>
              <CardDescription>
                Add any additional command-line arguments not covered above
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Textarea
                value={customArgs}
                onChange={(e) => setCustomArgs(e.target.value)}
                placeholder="--custom-flag value --another-option"
                className="font-mono text-sm"
                rows={3}
              />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Examples */}
        <TabsContent value="examples" className="space-y-4">
          <div className="grid gap-4">
            {Object.entries(tool.examples).map(([level, command]) => (
              <Card key={level}>
                <CardHeader>
                  <CardTitle className="text-lg capitalize">{level} Example</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="relative">
                    <pre className="bg-muted p-4 rounded-lg text-sm font-mono overflow-x-auto">
                      <code>{command}</code>
                    </pre>
                    <Button
                      size="sm"
                      variant="outline"
                      className="absolute top-2 right-2"
                      onClick={() => navigator.clipboard.writeText(command)}
                    >
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Generated Command */}
        <TabsContent value="command" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Terminal className="h-5 w-5" />
                  Generated Command
                </span>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={resetConfig}>
                    <RotateCcw className="h-3 w-3 mr-1" />
                    Reset
                  </Button>
                  <Button size="sm" variant="outline" onClick={copyCommand}>
                    <Copy className="h-3 w-3 mr-1" />
                    Copy
                  </Button>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="relative">
                <pre className="bg-secondary p-4 rounded-lg text-sm font-mono overflow-x-auto min-h-[60px] flex items-center">
                  <code>{generatedCommand || `${tool.name.toLowerCase()} [options] [target]`}</code>
                </pre>
              </div>
              
              {onExecute && (
                <Button 
                  onClick={onExecute}
                  disabled={isExecuting || !generatedCommand}
                  size="lg"
                  className="w-full"
                >
                  {isExecuting ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                      Executing...
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4 mr-2" />
                      Execute Command
                    </>
                  )}
                </Button>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};