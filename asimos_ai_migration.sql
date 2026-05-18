-- Optional AI log table for future analytics. Current AI endpoints work without this table.
create table if not exists public.ai_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id) on delete set null,
  feature text not null,
  input jsonb default '{}'::jsonb,
  output jsonb default '{}'::jsonb,
  created_at timestamptz default now()
);
create index if not exists idx_ai_logs_user_created on public.ai_logs(user_id, created_at desc);
create index if not exists idx_ai_logs_feature_created on public.ai_logs(feature, created_at desc);
