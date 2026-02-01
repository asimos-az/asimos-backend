create extension if not exists pgcrypto;

-- Optional: enable Expo push notifications
alter table public.profiles
  add column if not exists expo_push_token text;

-- Recommended: keep tokens in a separate table (more reliable across schema changes)
create table if not exists public.push_tokens (
  user_id uuid primary key references auth.users(id) on delete cascade,
  expo_push_token text not null,
  updated_at timestamptz not null default now()
);

create index if not exists push_tokens_updated_at_idx on public.push_tokens (updated_at desc);

-- Notifications inbox (in-app history)
create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  user_id uuid not null,
  title text not null,
  body text not null,
  data jsonb null,
  read_at timestamptz null
);

create index if not exists notifications_user_id_idx on public.notifications (user_id);
create index if not exists notifications_created_at_idx on public.notifications (created_at desc);
create index if not exists notifications_user_unread_idx on public.notifications (user_id) where read_at is null;

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
alter table public.jobs
  add column if not exists job_type text;

alter table public.jobs
  add column if not exists duration_days integer;

alter table public.jobs
  add column if not exists expires_at timestamptz;

-- Jobs lifecycle (open/closed)
alter table public.jobs
  add column if not exists status text not null default 'open';

alter table public.jobs
  add column if not exists closed_at timestamptz;

alter table public.jobs
  add column if not exists closed_reason text;

create index if not exists jobs_status_idx on public.jobs (status);

create index if not exists jobs_expires_at_idx on public.jobs (expires_at);

-- Backfill existing rows (safe)
update public.jobs
set status = 'open'
where status is null;

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

-- Categories (with optional sub-categories via parent_id)
create table if not exists public.categories (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  name text not null,
  slug text not null,
  sort integer not null default 0,
  is_active boolean not null default true,
  parent_id uuid null references public.categories(id) on delete set null
);

create unique index if not exists categories_slug_uniq on public.categories (slug);
create index if not exists categories_parent_id_idx on public.categories (parent_id);
create index if not exists categories_sort_idx on public.categories (sort);

-- Job contact fields (VOEN + phone + link)
alter table public.jobs
  add column if not exists voen text;

alter table public.jobs
  add column if not exists contact_phone text;

alter table public.jobs
  add column if not exists contact_link text;

-- Ratings System
create table if not exists public.ratings (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  reviewer_id uuid not null references public.profiles(id),
  target_id uuid not null references public.profiles(id),
  job_id uuid not null references public.jobs(id),
  score integer not null check (score >= 1 and score <= 5),
  comment text,
  unique (reviewer_id, job_id)
);

create index if not exists ratings_target_id_idx on public.ratings (target_id);
create index if not exists ratings_reviewer_id_idx on public.ratings (reviewer_id);

-- User Rating Stats
alter table public.profiles
  add column if not exists average_rating double precision default 0,
  add column if not exists rating_count integer default 0;

-- Job Boosting (Premium 1 week)
alter table public.jobs
  add column if not exists boosted_until timestamptz;

create index if not exists jobs_boosted_until_idx on public.jobs (boosted_until desc);


-- JOB ALERTS (İş Bildirişləri)
CREATE TABLE IF NOT EXISTS public.job_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
    query TEXT,          -- Açar söz (məs: "ofisiant", "sürücü")
    min_wage NUMERIC,
    max_wage NUMERIC,
    job_type TEXT,       -- 'permanent', 'temporary'
    location_lat NUMERIC,
    location_lng NUMERIC,
    radius_m INTEGER,    -- Xəritədə seçilən radius (metrlə)
    channel TEXT DEFAULT 'push', -- 'push', 'email', 'both' (gələcək üçün)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Index for faster matching
CREATE INDEX IF NOT EXISTS idx_job_alerts_user_id ON public.job_alerts(user_id);


-- NOTIFICATION QUEUE (Scheduled Batch Notifications)
-- Stores notifications to be sent at 08:00 and 19:00
CREATE TABLE IF NOT EXISTS public.notification_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    data JSONB,
    status TEXT DEFAULT 'pending', -- pending, sent, failed
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notification_queue_status ON public.notification_queue(status);

-- CONTENT PAGES (Terms, Privacy, etc.)
CREATE TABLE IF NOT EXISTS public.content_pages (
    slug TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Seed Initial Content
INSERT INTO public.content_pages (slug, title, body)
VALUES ('terms', 'Qaydalar və Şərtlər', 'Məzmun tezliklə əlavə olunacaq...')
ON CONFLICT (slug) DO NOTHING;
