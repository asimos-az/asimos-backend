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
