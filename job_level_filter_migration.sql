-- Optional filter support for vacancy position level
alter table public.jobs
  add column if not exists job_level text;

create index if not exists jobs_job_level_idx on public.jobs (job_level);
