
-- Add status to profiles (active, pending, suspended)
-- Default is active (so current users don't break)
alter table public.profiles 
  add column if not exists status text not null default 'active';

create index if not exists profiles_status_idx on public.profiles (status);

-- Backfill existing employers to active (safe default)
update public.profiles set status = 'active' where status is null;
