-- Add WhatsApp to existing site settings JSON in content_pages.
-- Run in Supabase SQL Editor if you already have the site-settings row.

create table if not exists public.content_pages (
  slug text primary key,
  title text,
  body text,
  updated_at timestamptz default now()
);

insert into public.content_pages (slug, title, body, updated_at)
values (
  'site-settings',
  'Site Settings',
  '{"socialLinks":{"facebook":"","instagram":"","tiktok":"","linkedin":"","twitter":"","telegram":"","whatsapp":""}}',
  now()
)
on conflict (slug) do update
set body = jsonb_set(
    coalesce(public.content_pages.body::jsonb, '{}'::jsonb),
    '{socialLinks,whatsapp}',
    coalesce(public.content_pages.body::jsonb #> '{socialLinks,whatsapp}', '""'::jsonb),
    true
  )::text,
  updated_at = now();
