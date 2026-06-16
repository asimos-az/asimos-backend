-- Modern job creation form fields
alter table public.jobs
  add column if not exists workplace text;

alter table public.jobs
  add column if not exists ats_link text;

alter table public.jobs
  add column if not exists contact_email text;

alter table public.jobs
  add column if not exists vacancy_start_date date;

alter table public.jobs
  add column if not exists vacancy_end_date date;

alter table public.jobs
  add column if not exists contact_visibility jsonb not null default '{"phone": true, "whatsapp": true, "email": true}'::jsonb;

alter table public.jobs
  add column if not exists primary_contact text not null default 'phone';

create index if not exists jobs_vacancy_dates_idx
  on public.jobs (vacancy_start_date, vacancy_end_date);
