create extension if not exists pgcrypto;

create table if not exists public.home_widgets (
  id uuid primary key default gen_random_uuid(),
  widget_key text not null unique,
  title text not null,
  button_label text,
  description text,
  email_to text,
  email_subject text,
  textarea_placeholder text,
  cta_label text,
  items jsonb not null default '[]'::jsonb,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists home_widgets_key_active_idx
  on public.home_widgets (widget_key, is_active, updated_at desc);

create or replace function public.set_home_widgets_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists home_widgets_set_updated_at on public.home_widgets;

create trigger home_widgets_set_updated_at
before update on public.home_widgets
for each row execute function public.set_home_widgets_updated_at();

insert into public.home_widgets (
  widget_key,
  title,
  button_label,
  items,
  is_active
)
values (
  'useful_info',
  'Faydalı məlumat',
  '📚 Faydalı məlumat',
  '[
    {"title":"Əmək Məcəlləsi (e-qanun.az)","url":"https://e-qanun.az/framework/46943","icon":"📥"},
    {"title":"DOST mərkəzləri — iş axtaranlar üçün","url":"https://dost.gov.az/","icon":"📥"},
    {"title":"Rəsmi VÖEN sorğusu","url":"https://www.e-taxes.gov.az/","icon":"📥"},
    {"title":"CV hazırlama bələdçisi","url":"https://asimos.az","icon":"📥"},
    {"title":"Müsahibəyə hazırlıq tövsiyələri","url":"https://asimos.az","icon":"📥"}
  ]'::jsonb,
  true
)
on conflict (widget_key) do nothing;

insert into public.home_widgets (
  widget_key,
  title,
  button_label,
  description,
  email_to,
  email_subject,
  textarea_placeholder,
  cta_label,
  is_active
)
values (
  'idea',
  'Yeni ideyan var?',
  '💡 Yeni ideyan var?',
  'Asimos.az-ı necə daha yaxşı edə bilərik? İdeyanı yaz, mail vasitəsilə bizə göndər.',
  'lduo4737@gmail.com',
  'Asimos.az üçün yeni ideya',
  'İdeyanı buraya yaz...',
  '✉️ Mail ilə göndər',
  true
)
on conflict (widget_key) do nothing;
