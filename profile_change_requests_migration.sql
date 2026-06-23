-- İşəgötürən paneli: dəyişiklik sorğuları
-- Supabase SQL Editor-də işlədin. Mövcud table varsa onu da düzəldir.

-- 1) profiles table üçün əlavə məlumat sahələri
alter table public.profiles add column if not exists voen text;
alter table public.profiles add column if not exists whatsapp text;
alter table public.profiles add column if not exists contact_email text;
alter table public.profiles add column if not exists ats_link text;

-- 2) Dəyişiklik sorğuları table-ı
create table if not exists public.profile_change_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid,
  field_key text not null,
  field_label text,
  db_column text,
  old_value text,
  new_value text,
  has_saved_value boolean default false,
  status text not null default 'pending',
  admin_note text,
  decided_by text,
  decided_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 3) Əgər table əvvəl yaranıbsa, çatışmayan column-ları əlavə et
alter table public.profile_change_requests add column if not exists user_id uuid;
alter table public.profile_change_requests add column if not exists field_key text;
alter table public.profile_change_requests add column if not exists field_label text;
alter table public.profile_change_requests add column if not exists db_column text;
alter table public.profile_change_requests add column if not exists old_value text;
alter table public.profile_change_requests add column if not exists new_value text;
alter table public.profile_change_requests add column if not exists has_saved_value boolean default false;
alter table public.profile_change_requests add column if not exists status text not null default 'pending';
alter table public.profile_change_requests add column if not exists admin_note text;
alter table public.profile_change_requests add column if not exists decided_by text;
alter table public.profile_change_requests add column if not exists decided_at timestamptz;
alter table public.profile_change_requests add column if not exists created_at timestamptz not null default now();
alter table public.profile_change_requests add column if not exists updated_at timestamptz not null default now();

-- 4) Status dəyərlərini təhlükəsiz normallaşdır
update public.profile_change_requests
set status = 'pending'
where status is null or status not in ('pending', 'approved', 'rejected');

alter table public.profile_change_requests
alter column status set default 'pending';

alter table public.profile_change_requests
alter column status set not null;

-- 5) Supabase relationship üçün foreign key. Admin paneldə profiles join bununla işləyir.
do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'profile_change_requests_user_id_fkey'
      and conrelid = 'public.profile_change_requests'::regclass
  ) then
    alter table public.profile_change_requests
      add constraint profile_change_requests_user_id_fkey
      foreign key (user_id)
      references public.profiles(id)
      on delete cascade;
  end if;
end $$;

-- 6) Index-lər
create index if not exists profile_change_requests_user_id_idx on public.profile_change_requests(user_id);
create index if not exists profile_change_requests_status_idx on public.profile_change_requests(status);
create index if not exists profile_change_requests_created_at_idx on public.profile_change_requests(created_at desc);

-- 7) updated_at trigger
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

-- 8) Schema cache reload üçün PostgREST notify
notify pgrst, 'reload schema';
