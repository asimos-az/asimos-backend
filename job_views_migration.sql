alter table public.jobs
add column if not exists views integer not null default 0;