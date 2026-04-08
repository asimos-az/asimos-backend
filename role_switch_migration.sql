-- Role switch requests
-- Seeker → Employer: admin approval required
-- Employer → Seeker: immediate (no approval), deletes all employer data

CREATE TABLE IF NOT EXISTS public.role_switch_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  from_role TEXT NOT NULL,
  to_role TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
  company_name TEXT,
  category TEXT,
  reviewer_note TEXT,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reviewed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS role_switch_requests_user_id_idx ON public.role_switch_requests (user_id);
CREATE INDEX IF NOT EXISTS role_switch_requests_status_idx ON public.role_switch_requests (status);
CREATE INDEX IF NOT EXISTS role_switch_requests_requested_at_idx ON public.role_switch_requests (requested_at DESC);
