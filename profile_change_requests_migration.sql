-- İşəgötürən paneli: dəyişiklik sorğuları
-- Supabase SQL Editor-də bir dəfə işlədin.

alter table public.profiles add column if not exists voen text;
alter table public.profiles add column if not exists whatsapp text;
alter table public.profiles add column if not exists contact_email text;
alter table public.profiles add column if not exists ats_link text;

create table if not exists public.profile_change_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  field_key text not null,
  field_label text,
  db_column text not null,
  old_value text,
  new_value text not null,
  has_saved_value boolean default false,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  admin_note text,
  decided_by text,
  decided_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists profile_change_requests_user_id_idx on public.profile_change_requests(user_id);
create index if not exists profile_change_requests_status_idx on public.profile_change_requests(status);
create index if not exists profile_change_requests_created_at_idx on public.profile_change_requests(created_at desc);

create or replace function public.set_profile_change_requests_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists trg_profile_change_requests_updated_at on public.profile_change_requests;
create trigger trg_profile_change_requests_updated_at
before update on public.profile_change_requests
for each row execute function public.set_profile_change_requests_updated_at();
