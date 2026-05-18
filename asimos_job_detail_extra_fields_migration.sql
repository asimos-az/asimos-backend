-- Asimos: extra job detail fields used by create/edit form
-- Run once in Supabase SQL Editor.

alter table public.jobs
  add column if not exists start_time text,
  add column if not exists end_time text,
  add column if not exists job_level text,
  add column if not exists voen text,
  add column if not exists contact_phone text,
  add column if not exists contact_link text,
  add column if not exists company_name text,
  add column if not exists image_url text,
  add column if not exists expires_at timestamptz,
  add column if not exists published_at timestamptz;

create index if not exists idx_jobs_expires_at on public.jobs(expires_at);
create index if not exists idx_jobs_job_level on public.jobs(job_level);
