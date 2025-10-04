import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.38.4';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface SearchParams {
  query: string;
  category?: string;
  tags?: string[];
  limit?: number;
  similarityThreshold?: number;
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { query, category, tags, limit = 5, similarityThreshold = 0.7 } = await req.json() as SearchParams;

    if (!query) {
      throw new Error('query is required');
    }

    console.log('Search request:', { query, category, tags, limit, similarityThreshold });

    const OPENAI_API_KEY = Deno.env.get('OPENAI_API_KEY');
    if (!OPENAI_API_KEY) {
      throw new Error('OPENAI_API_KEY not configured');
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    // Generate embedding for the query
    console.log('Generating embedding for query...');
    const embeddingResponse = await fetch('https://api.openai.com/v1/embeddings', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'text-embedding-3-small',
        input: query,
        dimensions: 1536,
      }),
    });

    if (!embeddingResponse.ok) {
      const errorText = await embeddingResponse.text();
      throw new Error(`OpenAI API error: ${embeddingResponse.status} - ${errorText}`);
    }

    const embeddingData = await embeddingResponse.json();
    const queryEmbedding = embeddingData.data[0].embedding;

    // Perform vector similarity search with filters
    console.log('Performing vector similarity search...');
    let vectorQuery = supabase.rpc('match_hacktricks_guides', {
      query_embedding: queryEmbedding,
      match_threshold: similarityThreshold,
      match_count: limit * 2, // Get more for filtering
    });

    // Apply category filter if provided
    if (category) {
      vectorQuery = vectorQuery.eq('category', category);
    }

    // Apply tags filter if provided (guides must have at least one matching tag)
    if (tags && tags.length > 0) {
      vectorQuery = vectorQuery.overlaps('tags', tags);
    }

    const { data: vectorResults, error: vectorError } = await vectorQuery;

    if (vectorError) {
      console.error('Vector search error:', vectorError);
      throw vectorError;
    }

    // Perform full-text search as a fallback/complement
    console.log('Performing full-text search...');
    let textQuery = supabase
      .from('hacktricks_guides')
      .select('*')
      .or(`title.ilike.%${query}%,content.ilike.%${query}%`)
      .limit(limit);

    if (category) {
      textQuery = textQuery.eq('category', category);
    }

    if (tags && tags.length > 0) {
      textQuery = textQuery.overlaps('tags', tags);
    }

    const { data: textResults, error: textError } = await textQuery;

    if (textError) {
      console.error('Text search error:', textError);
      throw textError;
    }

    // Merge and deduplicate results
    const resultsMap = new Map();
    
    // Add vector results with similarity scores
    if (vectorResults) {
      vectorResults.forEach((result: any) => {
        resultsMap.set(result.id, {
          ...result,
          relevance_score: result.similarity,
          match_type: 'semantic',
        });
      });
    }

    // Add text results (if not already present)
    if (textResults) {
      textResults.forEach((result: any) => {
        if (!resultsMap.has(result.id)) {
          resultsMap.set(result.id, {
            ...result,
            relevance_score: 0.5,
            match_type: 'keyword',
          });
        }
      });
    }

    // Convert to array and sort by relevance
    const mergedResults = Array.from(resultsMap.values())
      .sort((a, b) => b.relevance_score - a.relevance_score)
      .slice(0, limit);

    console.log(`Found ${mergedResults.length} relevant guides`);

    return new Response(
      JSON.stringify({
        success: true,
        results: mergedResults,
        count: mergedResults.length,
      }),
      {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    console.error('Error in search-hacktricks function:', error);
    return new Response(
      JSON.stringify({
        error: error.message || 'Internal server error',
        details: error.toString(),
      }),
      {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  }
});
