begin;

alter table public.profiles
  add column if not exists seeker_profile jsonb not null default '{}'::jsonb;

alter table public.profiles
  drop constraint if exists profiles_seeker_profile_object_check;

alter table public.profiles
  add constraint profiles_seeker_profile_object_check
  check (jsonb_typeof(seeker_profile) = 'object');

comment on column public.profiles.seeker_profile is
  'Private job-seeker preferences and profile-completion data managed through the authenticated profile API.';

commit;
