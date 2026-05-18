-- Jobs approval workflow support. Run in Supabase SQL Editor if your jobs.status is enum-based.
-- Existing projects using text status do not need enum changes, but this is safe.
do $$
begin
  if exists (select 1 from pg_type where typname = 'job_status') then
    alter type public.job_status add value if not exists 'pending';
    alter type public.job_status add value if not exists 'draft';
    alter type public.job_status add value if not exists 'rejected';
    alter type public.job_status add value if not exists 'deleted';
    alter type public.job_status add value if not exists 'scheduled';
  end if;
exception when duplicate_object then null;
end $$;

create index if not exists idx_jobs_status_created_at on public.jobs(status, created_at desc);
