-- Final Cleanup: Ensure all user data is deleted when profile is removed
-- Run this in the Supabase SQL Editor

-- 1. Ratings (Cascading deletes for both reviewer and target)
ALTER TABLE public.ratings 
DROP CONSTRAINT IF EXISTS ratings_reviewer_id_fkey,
DROP CONSTRAINT IF EXISTS ratings_target_id_fkey;

ALTER TABLE public.ratings
ADD CONSTRAINT ratings_reviewer_id_fkey 
  FOREIGN KEY (reviewer_id) REFERENCES public.profiles(id) ON DELETE CASCADE,
ADD CONSTRAINT ratings_target_id_fkey 
  FOREIGN KEY (target_id) REFERENCES public.profiles(id) ON DELETE CASCADE;

-- 2. Notifications (Add foreign key if missing + Cascade)
ALTER TABLE public.notifications 
DROP CONSTRAINT IF EXISTS notifications_user_id_fkey;

ALTER TABLE public.notifications
ADD CONSTRAINT notifications_user_id_fkey 
  FOREIGN KEY (user_id) REFERENCES public.profiles(id) ON DELETE CASCADE;

-- 3. Jobs (Ensure jobs are deleted if employer profile is gone)
ALTER TABLE public.jobs 
DROP CONSTRAINT IF EXISTS jobs_created_by_fkey;

ALTER TABLE public.jobs
ADD CONSTRAINT jobs_created_by_fkey 
  FOREIGN KEY (created_by) REFERENCES public.profiles(id) ON DELETE CASCADE;

-- 4. Events (Optional: keep events but nullify actor_id, or delete)
ALTER TABLE public.events 
DROP CONSTRAINT IF EXISTS events_actor_id_fkey;

ALTER TABLE public.events
ADD CONSTRAINT events_actor_id_fkey 
  FOREIGN KEY (actor_id) REFERENCES public.profiles(id) ON DELETE SET NULL;
