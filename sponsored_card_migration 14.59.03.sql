create extension if not exists pgcrypto;

create table if not exists public.sponsored_cards (
  id uuid primary key default gen_random_uuid(),
  card_type text not null default 'sponsored',
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
  sort_order integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.sponsored_cards
  add column if not exists card_type text not null default 'sponsored';

alter table public.sponsored_cards
  add column if not exists sort_order integer not null default 0;

update public.sponsored_cards
set
  card_type = case
    when position = 'after_4_jobs' then 'recommended'
    else coalesce(nullif(card_type, ''), 'sponsored')
  end,
  sort_order = case
    when position = 'after_4_jobs' then 4
    else coalesce(sort_order, 0)
  end,
  badge_label = case
    when position = 'after_4_jobs' and (badge_label is null or badge_label = 'Sponsorlu') then 'Tövsiyə olunur'
    else badge_label
  end
where true;

create unique index if not exists sponsored_cards_card_type_unique_idx
  on public.sponsored_cards (card_type);

create index if not exists sponsored_cards_active_position_idx
  on public.sponsored_cards (is_active, position, updated_at desc);

create index if not exists sponsored_cards_active_type_order_idx
  on public.sponsored_cards (is_active, card_type, sort_order, updated_at desc);

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
