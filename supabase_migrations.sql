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


-- Kateqoriyalar (Admin Paneldən idarə olunur, mobil tərəfdə select kimi istifadə olunur)
create table if not exists public.categories (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  name text not null,
  slug text not null,
  sort int not null default 0,
  is_active boolean not null default true
);

-- Unique constraints (safe if already exists)
do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'categories_name_key'
  ) then
    alter table public.categories add constraint categories_name_key unique (name);
  end if;

  if not exists (
    select 1 from pg_constraint where conname = 'categories_slug_key'
  ) then
    alter table public.categories add constraint categories_slug_key unique (slug);
  end if;
end $$;

create index if not exists categories_sort_idx on public.categories (sort, created_at);
create index if not exists categories_active_idx on public.categories (is_active);
