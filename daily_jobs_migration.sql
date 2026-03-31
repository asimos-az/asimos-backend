-- Add fields for daily/temporary jobs
ALTER TABLE public.jobs 
ADD COLUMN IF NOT EXISTS starts_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS working_hours TEXT;

-- Update existing temporary jobs to have a start date if null (using created_at as fallback)
UPDATE public.jobs 
SET starts_at = created_at 
WHERE job_type = 'temporary' AND starts_at IS NULL;
