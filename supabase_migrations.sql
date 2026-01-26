create extension if not exists pgcrypto;

-- Optional: enable Expo push notifications
-- Add a column to store Expo push token
alter table public.profiles
  add column if not exists expo_push_token text;

-- (Optional) You may want an index, if you later query by token
-- create index if not exists profiles_expo_push_token_idx on public.profiles (expo_push_token);


-- Admin Panel activity feed (events)
create table if not exists public.events (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  type text not null,
  actor_id uuid null,
  metadata jsonb null
);

create index if not exists events_created_at_idx on public.events (created_at desc);
create index if not exists events_type_idx on public.events (type);
create index if not exists events_actor_id_idx on public.events (actor_id);

-- Jobs auto-expiry (Daimi / Müvəqqəti)
-- Daimi: 28 gün sonra avtomatik silinir
-- Müvəqqəti: seçilən gün sayı bitəndə avtomatik silinir
alter table public.jobs
  add column if not exists job_type text;

alter table public.jobs
  add column if not exists duration_days integer;

alter table public.jobs
  add column if not exists expires_at timestamptz;

create index if not exists jobs_expires_at_idx on public.jobs (expires_at);

-- Backfill existing rows
update public.jobs
set job_type = case when coalesce(is_daily, false) then 'temporary' else 'permanent' end
where job_type is null;

update public.jobs
set duration_days = 1
where job_type = 'temporary' and duration_days is null;

update public.jobs
set expires_at = case
  when job_type = 'temporary' then created_at + (coalesce(duration_days, 1) * interval '1 day')
  else created_at + interval '28 days'
end
where expires_at is null;
