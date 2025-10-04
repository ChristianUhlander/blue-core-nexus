import React, { useState, useRef, useEffect } from 'react';
import { MessageCircle, X, Send, Bot, User } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Card } from '@/components/ui/card';
import { supabase } from '@/integrations/supabase/client';
import { toast } from '@/hooks/use-toast';

interface Message {
  id: string;
  content: string;
  isUser: boolean;
  timestamp: Date;
}

interface IppsYChatPaneProps {
  isOpen: boolean;
  onToggle: () => void;
}

const IppsYChatPane = ({ isOpen, onToggle }: IppsYChatPaneProps) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      content: "Hello! I'm IppsY, your AI Security Assistant. I can help analyze logs, answer security questions, and provide insights about your security infrastructure. What would you like to know?",
      isUser: false,
      timestamp: new Date(),
    },
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  
  // Load active profile config
  const [profileConfig, setProfileConfig] = useState<any>(null);
  
  useEffect(() => {
    const loadProfile = () => {
      const savedProfiles = localStorage.getItem('llm_profiles');
      const savedActiveProfile = localStorage.getItem('active_llm_profile');
      
      if (savedProfiles && savedActiveProfile) {
        const profiles = JSON.parse(savedProfiles);
        const activeProfile = profiles.find((p: any) => p.id === savedActiveProfile);
        
        if (activeProfile) {
          setProfileConfig(activeProfile);
          console.log('iPPSY loaded profile:', activeProfile.name);
        }
      } else {
        // Default to Lovable AI if no profile configured
        setProfileConfig({
          name: 'Default',
          config: {
            provider: 'lovable-ai',
            model: 'google/gemini-2.5-flash',
            temperature: 0.7,
            maxTokens: 2000
          },
          apiKey: ''
        });
      }
    };
    
    loadProfile();
  }, []);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSendMessage = async () => {
    if (!inputMessage.trim()) return;
    
    if (!profileConfig) {
      toast({
        title: "Configuration Error",
        description: "Please configure an AI profile in Settings",
        variant: "destructive"
      });
      return;
    }

    const userMessage: Message = {
      id: Date.now().toString(),
      content: inputMessage,
      isUser: true,
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsTyping(true);

    try {
      // Prepare conversation history for AI
      const conversationMessages = messages
        .filter(m => m.id !== '1') // Exclude initial greeting
        .map(m => ({
          role: m.isUser ? 'user' : 'assistant',
          content: m.content
        }));
      
      conversationMessages.push({
        role: 'user',
        content: userMessage.content
      });

      console.log('Calling iPPSY chat with profile:', profileConfig.name);
      
      const { data, error } = await supabase.functions.invoke('ippsy-chat', {
        body: {
          messages: conversationMessages,
          provider: profileConfig.config.provider,
          model: profileConfig.config.model,
          apiKey: profileConfig.apiKey,
          temperature: profileConfig.config.temperature,
          maxTokens: profileConfig.config.maxTokens
        }
      });

      if (error) {
        console.error('iPPSY chat error:', error);
        throw error;
      }

      const aiContent = data.choices?.[0]?.message?.content || 'Sorry, I could not generate a response.';
      
      const aiResponse: Message = {
        id: (Date.now() + 1).toString(),
        content: aiContent,
        isUser: false,
        timestamp: new Date(),
      };
      
      setMessages(prev => [...prev, aiResponse]);
    } catch (error) {
      console.error('Error sending message:', error);
      
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        content: `Error: ${error.message || 'Failed to get response. Please check your configuration and try again.'}`,
        isUser: false,
        timestamp: new Date(),
      };
      
      setMessages(prev => [...prev, errorMessage]);
      
      toast({
        title: "Chat Error",
        description: error.message || "Failed to communicate with AI",
        variant: "destructive"
      });
    } finally {
      setIsTyping(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="h-full flex flex-col border-l border-border/30 bg-gradient-to-b from-background/95 to-muted/20 backdrop-blur-sm">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-border/30 bg-gradient-to-r from-primary/5 to-muted/10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-full bg-gradient-to-r from-primary/20 to-blue-500/20">
            <Bot className="h-5 w-5 text-primary animate-pulse" />
          </div>
          <div>
            <h3 className="font-bold text-lg text-glow bg-gradient-to-r from-primary to-blue-400 bg-clip-text text-transparent">IppsY</h3>
            <p className="text-xs text-muted-foreground">AI Security Assistant</p>
          </div>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={onToggle}
          className="hover:bg-destructive/20 transition-all duration-200"
        >
          <X className="h-4 w-4" />
        </Button>
      </div>

      {/* Messages */}
      <ScrollArea className="flex-1 p-4">
          <div className="space-y-4">
            {messages.map((message) => (
              <div
                key={message.id}
                className={`flex ${message.isUser ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`flex items-start gap-2 max-w-[80%] ${
                    message.isUser ? 'flex-row-reverse' : 'flex-row'
                  }`}
                >
                  <div className={`p-2 rounded-lg ${
                    message.isUser
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-muted gradient-card'
                  }`}>
                    {message.isUser ? (
                      <User className="h-4 w-4" />
                    ) : (
                      <Bot className="h-4 w-4 text-primary" />
                    )}
                  </div>
                  <div
                    className={`p-3 rounded-lg ${
                      message.isUser
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-muted/50 gradient-card border border-border/30'
                    }`}
                  >
                    <p className="text-sm">{message.content}</p>
                    <span className="text-xs opacity-70 mt-1 block">
                      {message.timestamp.toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              </div>
            ))}
            
            {isTyping && (
              <div className="flex justify-start">
                <div className="flex items-start gap-2">
                  <div className="p-2 rounded-lg bg-muted gradient-card">
                    <Bot className="h-4 w-4 text-primary animate-pulse" />
                  </div>
                  <div className="p-3 rounded-lg bg-muted/50 gradient-card border border-border/30">
                    <div className="flex gap-1">
                      <div className="w-2 h-2 bg-primary rounded-full animate-bounce"></div>
                      <div className="w-2 h-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                      <div className="w-2 h-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                    </div>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>
        </ScrollArea>

      {/* Input */}
      <div className="p-4 border-t border-border/30 bg-gradient-to-r from-muted/20 to-background/50">
        <div className="flex gap-2">
          <Input
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Ask IppsY about security insights..."
            className="flex-1 bg-background/50 border-border/50 focus:border-primary transition-all duration-200"
          />
          <Button
            onClick={handleSendMessage}
            disabled={!inputMessage.trim() || isTyping}
            className="glow-hover transition-all duration-200"
          >
            <Send className="h-4 w-4" />
          </Button>
        </div>
        <p className="text-xs text-muted-foreground mt-2">
          🤖 {profileConfig ? `Using: ${profileConfig.name} (${profileConfig.config.provider})` : 'Loading configuration...'}
        </p>
      </div>
    </div>
  );
};

export default IppsYChatPane;