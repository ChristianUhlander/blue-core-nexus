import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.38.4';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { messages, provider, model, apiKey, temperature, maxTokens, context } = await req.json();

    console.log('iPPSY Chat request:', { provider, model, messagesCount: messages.length });

    // Retrieve relevant HackTricks guides if context is provided
    let retrievedContext = '';
    if (context && (context.query || context.goal || context.target)) {
      console.log('Retrieving relevant HackTricks guides...');
      
      const OPENAI_API_KEY = Deno.env.get('OPENAI_API_KEY');
      const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
      const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
      const supabase = createClient(supabaseUrl, supabaseKey);

      try {
        // Build search query from context
        const searchQuery = [
          context.query,
          context.goal,
          context.target,
          context.results
        ].filter(Boolean).join(' ');

        // Generate embedding for the search query
        const embeddingResponse = await fetch('https://api.openai.com/v1/embeddings', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${OPENAI_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'text-embedding-3-small',
            input: searchQuery,
            dimensions: 1536,
          }),
        });

        if (embeddingResponse.ok) {
          const embeddingData = await embeddingResponse.json();
          const queryEmbedding = embeddingData.data[0].embedding;

          // Search for relevant guides
          const { data: guides, error: searchError } = await supabase.rpc('match_hacktricks_guides', {
            query_embedding: queryEmbedding,
            match_threshold: 0.7,
            match_count: 3,
          });

          if (!searchError && guides && guides.length > 0) {
            console.log(`Found ${guides.length} relevant guides`);
            retrievedContext = '\n\n## Relevant HackTricks Guides:\n\n' + 
              guides.map((guide: any) => 
                `### ${guide.title}\n${guide.content.substring(0, 1000)}...\n`
              ).join('\n');
          }
        }
      } catch (error) {
        console.error('Error retrieving HackTricks context:', error);
        // Continue without context rather than failing
      }
    }

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

You have access to a comprehensive library of HackTricks guides. When relevant guides are provided in the context, use them to enhance your responses with specific techniques, commands, and strategies.

Provide clear, actionable advice with technical depth when appropriate.${retrievedContext}`
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

You have access to a comprehensive library of HackTricks guides. When relevant guides are provided in the context, use them to enhance your responses with specific techniques, commands, and strategies.

Provide clear, actionable advice with technical depth when appropriate.${retrievedContext}`
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
