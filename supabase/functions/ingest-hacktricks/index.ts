import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.38.4';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface Guide {
  title: string;
  content: string;
  category?: string;
  tags?: string[];
  url?: string;
  metadata?: Record<string, any>;
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { guides } = await req.json() as { guides: Guide[] };

    if (!Array.isArray(guides) || guides.length === 0) {
      throw new Error('guides must be a non-empty array');
    }

    console.log(`Processing ${guides.length} guides for ingestion`);

    const OPENAI_API_KEY = Deno.env.get('OPENAI_API_KEY');
    if (!OPENAI_API_KEY) {
      throw new Error('OPENAI_API_KEY not configured');
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    const results = [];
    let successCount = 0;
    let errorCount = 0;

    // Process guides in batches of 10
    const batchSize = 10;
    for (let i = 0; i < guides.length; i += batchSize) {
      const batch = guides.slice(i, i + batchSize);
      
      // Generate embeddings for the batch
      const embeddings = await Promise.all(
        batch.map(async (guide) => {
          try {
            const textToEmbed = `${guide.title}\n\n${guide.content}`;
            
            const embeddingResponse = await fetch('https://api.openai.com/v1/embeddings', {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${OPENAI_API_KEY}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                model: 'text-embedding-3-small',
                input: textToEmbed,
                dimensions: 1536,
              }),
            });

            if (!embeddingResponse.ok) {
              const errorText = await embeddingResponse.text();
              throw new Error(`OpenAI API error: ${embeddingResponse.status} - ${errorText}`);
            }

            const embeddingData = await embeddingResponse.json();
            return {
              ...guide,
              embedding: embeddingData.data[0].embedding,
            };
          } catch (error) {
            console.error(`Error generating embedding for "${guide.title}":`, error);
            return null;
          }
        })
      );

      // Insert guides with embeddings
      for (const guideWithEmbedding of embeddings) {
        if (!guideWithEmbedding) {
          errorCount++;
          continue;
        }

        try {
          const { error } = await supabase
            .from('hacktricks_guides')
            .insert({
              title: guideWithEmbedding.title,
              content: guideWithEmbedding.content,
              category: guideWithEmbedding.category,
              tags: guideWithEmbedding.tags,
              url: guideWithEmbedding.url,
              embedding: guideWithEmbedding.embedding,
              metadata: guideWithEmbedding.metadata || {},
            });

          if (error) {
            console.error(`Error inserting guide "${guideWithEmbedding.title}":`, error);
            errorCount++;
            results.push({ title: guideWithEmbedding.title, status: 'error', error: error.message });
          } else {
            successCount++;
            results.push({ title: guideWithEmbedding.title, status: 'success' });
          }
        } catch (error) {
          console.error(`Error inserting guide "${guideWithEmbedding.title}":`, error);
          errorCount++;
          results.push({ title: guideWithEmbedding.title, status: 'error', error: error.message });
        }
      }

      console.log(`Processed batch ${Math.floor(i / batchSize) + 1} of ${Math.ceil(guides.length / batchSize)}`);
    }

    console.log(`Ingestion complete: ${successCount} successful, ${errorCount} errors`);

    return new Response(
      JSON.stringify({
        success: true,
        total: guides.length,
        successCount,
        errorCount,
        results,
      }),
      {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  } catch (error) {
    console.error('Error in ingest-hacktricks function:', error);
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
