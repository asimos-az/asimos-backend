-- Asimos favorites support for saved job ads
-- Run in Supabase SQL Editor.

create table if not exists public.job_favorites (
  user_id uuid not null references public.profiles(id) on delete cascade,
  job_id uuid not null references public.jobs(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, job_id)
);

create index if not exists idx_job_favorites_user_created on public.job_favorites(user_id, created_at desc);
create index if not exists idx_job_favorites_job on public.job_favorites(job_id);

alter table public.job_favorites enable row level security;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename = 'job_favorites'
      and policyname = 'Users can read own job favorites'
  ) then
    create policy "Users can read own job favorites"
      on public.job_favorites for select
      using (auth.uid() = user_id);
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename = 'job_favorites'
      and policyname = 'Users can insert own job favorites'
  ) then
    create policy "Users can insert own job favorites"
      on public.job_favorites for insert
      with check (auth.uid() = user_id);
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'public'
      and tablename = 'job_favorites'
      and policyname = 'Users can delete own job favorites'
  ) then
    create policy "Users can delete own job favorites"
      on public.job_favorites for delete
      using (auth.uid() = user_id);
  end if;
end $$;
