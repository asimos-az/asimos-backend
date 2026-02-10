-- Support Tickets System

create table if not exists public.support_tickets (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  subject text,
  message text not null,
  status text not null default 'open', -- open, replied, closed
  is_answered boolean default false
);

create index if not exists support_tickets_user_id_idx on public.support_tickets (user_id);
create index if not exists support_tickets_status_idx on public.support_tickets (status);

-- Optional: If we want a separate table for replies, but for simplicity we can just append to a 'messages' array or use a separate table.
-- Let's use a separate table for history/replies to be robust.

create table if not exists public.support_messages (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  ticket_id uuid not null references public.support_tickets(id) on delete cascade,
  sender_id uuid null, -- if null, maybe system? or just use user_id. IF admin, how to store? Admin might not have a uuid in profiles if super admin.
  -- Let's say: sender_id is UUID. If it matches ticket.user_id, it's user. If not (or if we add a 'is_admin' flag), it's admin.
  is_admin boolean default false,
  message text not null
);

create index if not exists support_messages_ticket_id_idx on public.support_messages (ticket_id);
