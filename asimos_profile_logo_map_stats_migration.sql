-- Asimos profile logo, company logo and stats support
alter table public.profiles add column if not exists logo_url text;
alter table public.profiles add column if not exists company_name text;
alter table public.profiles add column if not exists last_seen_at timestamptz;

alter table public.jobs add column if not exists company_logo_url text;
alter table public.jobs add column if not exists company_name text;

create index if not exists idx_profiles_role_logo on public.profiles(role, company_name);
create index if not exists idx_jobs_company_logo on public.jobs(company_logo_url);
create index if not exists idx_jobs_open_location on public.jobs(status, location_lat, location_lng);
