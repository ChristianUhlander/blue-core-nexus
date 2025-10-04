-- Enable pgvector extension for vector similarity search
CREATE EXTENSION IF NOT EXISTS vector;

-- Create hacktricks_guides table
CREATE TABLE public.hacktricks_guides (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  category TEXT,
  tags TEXT[],
  url TEXT,
  embedding vector(1536),
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create index for vector similarity search
CREATE INDEX hacktricks_guides_embedding_idx ON public.hacktricks_guides 
USING ivfflat (embedding vector_cosine_ops)
WITH (lists = 100);

-- Create index for full-text search on title and content
CREATE INDEX hacktricks_guides_search_idx ON public.hacktricks_guides 
USING gin(to_tsvector('english', title || ' ' || content));

-- Create index for category filtering
CREATE INDEX hacktricks_guides_category_idx ON public.hacktricks_guides(category);

-- Create index for tags filtering
CREATE INDEX hacktricks_guides_tags_idx ON public.hacktricks_guides USING gin(tags);

-- Enable Row Level Security
ALTER TABLE public.hacktricks_guides ENABLE ROW LEVEL SECURITY;

-- Create policy: Allow public read access (guides are reference material)
CREATE POLICY "Hacktricks guides are publicly readable"
ON public.hacktricks_guides
FOR SELECT
USING (true);

-- Create policy: Only authenticated users can insert guides
CREATE POLICY "Authenticated users can insert guides"
ON public.hacktricks_guides
FOR INSERT
WITH CHECK (auth.uid() IS NOT NULL);

-- Create policy: Only authenticated users can update guides
CREATE POLICY "Authenticated users can update guides"
ON public.hacktricks_guides
FOR UPDATE
USING (auth.uid() IS NOT NULL);

-- Create policy: Only authenticated users can delete guides
CREATE POLICY "Authenticated users can delete guides"
ON public.hacktricks_guides
FOR DELETE
USING (auth.uid() IS NOT NULL);

-- Create function to update timestamps
CREATE OR REPLACE FUNCTION public.update_hacktricks_guides_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = public;

-- Create trigger for automatic timestamp updates
CREATE TRIGGER update_hacktricks_guides_updated_at
BEFORE UPDATE ON public.hacktricks_guides
FOR EACH ROW
EXECUTE FUNCTION public.update_hacktricks_guides_updated_at();