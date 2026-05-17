-- Asimos full update: job image, filters, draft/status, notifications, analytics/statistics
-- Run in Supabase SQL Editor.

alter table public.jobs
  add column if not exists job_level text,
  add column if not exists image_url text,
  add column if not exists published_at timestamptz,
  add column if not exists closed_at timestamptz,
  add column if not exists closed_reason text,
  add column if not exists rejection_reason text;

alter table public.profiles
  add column if not exists last_seen_at timestamptz;

do $$
begin
  if exists (select 1 from pg_type where typname = 'job_status') then
    alter type public.job_status add value if not exists 'draft';
    alter type public.job_status add value if not exists 'deleted';
    alter type public.job_status add value if not exists 'rejected';
    alter type public.job_status add value if not exists 'pending';
    alter type public.job_status add value if not exists 'scheduled';
  end if;
exception when duplicate_object then null;
end $$;

create table if not exists public.content_pages (
  slug text primary key,
  title text,
  body text,
  updated_at timestamptz default now()
);

insert into public.content_pages (slug, title, body, updated_at)
values (
  'job-filter-options',
  'Job Filter Options',
  '{"vacancyTypes":[{"label":"Növbə əsasında","value":"shift"},{"label":"Tam ştat","value":"full_time"},{"label":"Daimi","value":"permanent"},{"label":"Frilans","value":"freelance"},{"label":"Komisyon haqqı","value":"commission"},{"label":"Könüllü","value":"volunteer"},{"label":"Mövsümi","value":"seasonal"},{"label":"Müvəqqəti","value":"temporary"},{"label":"Təcrübə","value":"internship"},{"label":"Təqaüd proqramı","value":"scholarship"},{"label":"Yarım ştat","value":"part_time"}],"jobLevels":[{"label":"Təcrübəsiz","value":"entry"},{"label":"Junior","value":"junior"},{"label":"Middle","value":"middle"},{"label":"Senior","value":"senior"},{"label":"Menecer","value":"manager"},{"label":"Rəhbər","value":"lead"}],"salaryRanges":[{"label":"0 - 500 AZN","min":"0","max":"500"},{"label":"500 - 1000 AZN","min":"500","max":"1000"},{"label":"1000 - 1500 AZN","min":"1000","max":"1500"},{"label":"1500 - 2500 AZN","min":"1500","max":"2500"},{"label":"2500+ AZN","min":"2500","max":""}]}',
  now()
) on conflict (slug) do nothing;

create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id) on delete cascade,
  title text not null,
  body text,
  data jsonb default '{}'::jsonb,
  read_at timestamptz,
  created_at timestamptz default now()
);

create index if not exists idx_notifications_user_created on public.notifications(user_id, created_at desc);
create index if not exists idx_notifications_user_unread on public.notifications(user_id) where read_at is null;

create table if not exists public.site_visits (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id) on delete set null,
  session_id text,
  path text,
  user_agent text,
  created_at timestamptz default now()
);

create index if not exists idx_site_visits_created_at on public.site_visits(created_at desc);
create index if not exists idx_site_visits_session on public.site_visits(session_id);
create index if not exists idx_profiles_last_seen_at on public.profiles(last_seen_at desc);
