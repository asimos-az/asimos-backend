-- Add published_at column to jobs table
ALTER TABLE IF EXISTS public.jobs
ADD COLUMN IF NOT EXISTS published_at TIMESTAMP WITH TIME ZONE;

-- Index for performance when filtering by published_at
CREATE INDEX IF NOT EXISTS jobs_published_at_idx ON public.jobs (published_at);
