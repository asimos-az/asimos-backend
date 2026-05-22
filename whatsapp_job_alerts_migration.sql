-- Asimos WhatsApp job alerts + required phone support
-- Run this in Supabase SQL Editor.

alter table public.profiles
  add column if not exists phone text,
  add column if not exists whatsapp_opt_in boolean not null default false,
  add column if not exists whatsapp_opt_in_at timestamptz,
  add column if not exists whatsapp_last_job_alert_at timestamptz;

create index if not exists idx_profiles_role_whatsapp_opt_in
on public.profiles(role, whatsapp_opt_in);

create index if not exists idx_profiles_phone
on public.profiles(phone);

create table if not exists public.whatsapp_job_alert_logs (
  id uuid primary key default gen_random_uuid(),
  job_id uuid references public.jobs(id) on delete cascade,
  user_id uuid references public.profiles(id) on delete set null,
  phone text not null,
  status text not null default 'pending',
  provider_message_id text,
  error text,
  created_at timestamptz not null default now(),
  sent_at timestamptz
);

create index if not exists idx_whatsapp_job_alert_logs_job_id
on public.whatsapp_job_alert_logs(job_id, created_at desc);

create index if not exists idx_whatsapp_job_alert_logs_user_id
on public.whatsapp_job_alert_logs(user_id, created_at desc);

create index if not exists idx_whatsapp_job_alert_logs_status
on public.whatsapp_job_alert_logs(status, created_at desc);
