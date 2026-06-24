-- Role switch requests
-- Seeker → Employer: admin approval required
-- Employer → Seeker: immediate (no approval), deletes employer data

CREATE TABLE IF NOT EXISTS public.role_switch_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
  from_role TEXT,
  to_role TEXT,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
  company_name TEXT,
  voen TEXT,
  category TEXT,
  reviewer_note TEXT,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reviewed_at TIMESTAMPTZ
);

ALTER TABLE public.role_switch_requests
  ADD COLUMN IF NOT EXISTS user_id UUID,
  ADD COLUMN IF NOT EXISTS from_role TEXT,
  ADD COLUMN IF NOT EXISTS to_role TEXT,
  ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS company_name TEXT,
  ADD COLUMN IF NOT EXISTS voen TEXT,
  ADD COLUMN IF NOT EXISTS category TEXT,
  ADD COLUMN IF NOT EXISTS reviewer_note TEXT,
  ADD COLUMN IF NOT EXISTS requested_at TIMESTAMPTZ DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;

UPDATE public.role_switch_requests
SET requested_at = COALESCE(requested_at, NOW())
WHERE requested_at IS NULL;

ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS company_name TEXT,
  ADD COLUMN IF NOT EXISTS category TEXT,
  ADD COLUMN IF NOT EXISTS voen TEXT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.table_constraints
    WHERE constraint_schema = 'public'
      AND table_name = 'role_switch_requests'
      AND constraint_name = 'role_switch_requests_user_id_fkey'
  ) THEN
    ALTER TABLE public.role_switch_requests
    ADD CONSTRAINT role_switch_requests_user_id_fkey
    FOREIGN KEY (user_id)
    REFERENCES public.profiles(id)
    ON DELETE CASCADE;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS role_switch_requests_user_id_idx ON public.role_switch_requests (user_id);
CREATE INDEX IF NOT EXISTS role_switch_requests_status_idx ON public.role_switch_requests (status);
CREATE INDEX IF NOT EXISTS role_switch_requests_requested_at_idx ON public.role_switch_requests (requested_at DESC);

NOTIFY pgrst, 'reload schema';
