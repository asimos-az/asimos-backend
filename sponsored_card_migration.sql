create extension if not exists pgcrypto;

create table if not exists public.sponsored_cards (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  company_name text,
  subtitle text,
  description text,
  cta_label text default 'Ətraflı bax',
  cta_url text,
  logo_text text default 'AS',
  badge_label text default 'Sponsorlu',
  is_active boolean not null default true,
  position text not null default 'latest_jobs',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists sponsored_cards_active_position_idx
  on public.sponsored_cards (is_active, position, updated_at desc);

create or replace function public.set_sponsored_cards_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists sponsored_cards_set_updated_at on public.sponsored_cards;
create trigger sponsored_cards_set_updated_at
before update on public.sponsored_cards
for each row execute function public.set_sponsored_cards_updated_at();
