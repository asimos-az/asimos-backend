-- Optional: enable Expo push notifications
-- Add a column to store Expo push token
alter table public.profiles
  add column if not exists expo_push_token text;

-- (Optional) You may want an index, if you later query by token
-- create index if not exists profiles_expo_push_token_idx on public.profiles (expo_push_token);
