-- Employer profile panel fields
alter table public.profiles add column if not exists voen text;
alter table public.profiles add column if not exists whatsapp text;
alter table public.profiles add column if not exists contact_email text;
alter table public.profiles add column if not exists ats_link text;
