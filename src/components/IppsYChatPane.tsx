import React, { useState, useRef, useEffect } from 'react';
import { MessageCircle, X, Send, Bot, User } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Card } from '@/components/ui/card';

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

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSendMessage = async () => {
    if (!inputMessage.trim()) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      content: inputMessage,
      isUser: true,
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsTyping(true);

    // Simulate AI response (replace with actual Ollama API call later)
    setTimeout(() => {
      const aiResponse: Message = {
        id: (Date.now() + 1).toString(),
        content: "I understand your security inquiry. Currently, I'm waiting for the Ollama API connection to be established. Once connected, I'll provide detailed security analysis and insights based on your local security-tuned LLM.",
        isUser: false,
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, aiResponse]);
      setIsTyping(false);
    }, 1000);
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
          🤖 IppsY is ready to help with security analysis
        </p>
      </div>
    </div>
  );
};

export default IppsYChatPane;