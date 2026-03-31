-- Add rejection_reason to jobs table
ALTER TABLE public.jobs 
ADD COLUMN IF NOT EXISTS rejection_reason TEXT;

-- Update status indexes if needed (already exists from previous migrations)
-- Index for status is important for the new multi-stage filters
CREATE INDEX IF NOT EXISTS idx_jobs_status_owner ON public.jobs (created_by, status);
