
-- Add status to profiles (active, pending, suspended)
-- Default is active (so current users don't break)
alter table public.profiles 
  add column if not exists status text not null default 'active';

create index if not exists profiles_status_idx on public.profiles (status);

-- Backfill existing employers to active (safe default)
update public.profiles set status = 'active' where status is null;

-- Add status to jobs (open, closed, pending)
-- Default is open (so current jobs remain visible)
alter table public.jobs 
  add column if not exists status text not null default 'open';

create index if not exists jobs_status_idx on public.jobs (status);

-- Backfill existing jobs to open
update public.jobs set status = 'open' where status is null;
