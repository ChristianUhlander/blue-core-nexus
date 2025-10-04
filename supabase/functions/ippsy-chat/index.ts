import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { messages, provider, model, apiKey, temperature, maxTokens } = await req.json();

    console.log('iPPSY Chat request:', { provider, model, messagesCount: messages.length });

    let response;
    let apiUrl;
    let headers;
    let body;

    if (provider === 'lovable-ai') {
      // Use Lovable AI Gateway
      const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');
      if (!LOVABLE_API_KEY) {
        throw new Error('LOVABLE_API_KEY not configured');
      }

      apiUrl = 'https://ai.gateway.lovable.dev/v1/chat/completions';
      headers = {
        'Authorization': `Bearer ${LOVABLE_API_KEY}`,
        'Content-Type': 'application/json',
      };
      body = {
        model: model || 'google/gemini-2.5-flash',
        messages: [
          {
            role: 'system',
            content: `You are iPPSY, an AI Security Assistant specializing in cybersecurity analysis, penetration testing, and security infrastructure management. You provide expert guidance on:
- Security vulnerability analysis
- Penetration testing strategies
- Security tool configuration (Wazuh, GVM, ZAP, etc.)
- Threat intelligence
- Security best practices
- Incident response

Provide clear, actionable advice with technical depth when appropriate.`
          },
          ...messages
        ],
        temperature: temperature || 0.7,
        max_tokens: maxTokens || 2000,
      };
    } else if (provider === 'openai') {
      // Use OpenAI API
      if (!apiKey) {
        throw new Error('OpenAI API key not provided');
      }

      apiUrl = 'https://api.openai.com/v1/chat/completions';
      headers = {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      };
      body = {
        model: model || 'gpt-5-2025-08-07',
        messages: [
          {
            role: 'system',
            content: `You are iPPSY, an AI Security Assistant specializing in cybersecurity analysis, penetration testing, and security infrastructure management. You provide expert guidance on:
- Security vulnerability analysis
- Penetration testing strategies
- Security tool configuration (Wazuh, GVM, ZAP, etc.)
- Threat intelligence
- Security best practices
- Incident response

Provide clear, actionable advice with technical depth when appropriate.`
          },
          ...messages
        ],
        temperature: temperature || 0.7,
        max_completion_tokens: maxTokens || 2000,
      };
    } else {
      throw new Error(`Unsupported provider: ${provider}`);
    }

    console.log('Making request to:', apiUrl);
    response = await fetch(apiUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('AI API error:', response.status, errorText);
      throw new Error(`AI API error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    console.log('AI response received');

    return new Response(JSON.stringify(data), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Error in ippsy-chat function:', error);
    return new Response(JSON.stringify({ 
      error: error.message || 'Internal server error',
      details: error.toString()
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
