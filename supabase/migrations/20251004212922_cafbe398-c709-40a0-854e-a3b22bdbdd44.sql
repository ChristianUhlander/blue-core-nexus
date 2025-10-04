-- Fix search path for match_hacktricks_guides function
create or replace function match_hacktricks_guides(
  query_embedding vector(1536),
  match_threshold float default 0.7,
  match_count int default 5
)
returns table (
  id uuid,
  title text,
  content text,
  category text,
  tags text[],
  url text,
  metadata jsonb,
  created_at timestamptz,
  updated_at timestamptz,
  similarity float
)
language sql
stable
set search_path = public
as $$
  select
    id,
    title,
    content,
    category,
    tags,
    url,
    metadata,
    created_at,
    updated_at,
    1 - (embedding <=> query_embedding) as similarity
  from hacktricks_guides
  where 1 - (embedding <=> query_embedding) > match_threshold
  order by embedding <=> query_embedding
  limit match_count;
$$;