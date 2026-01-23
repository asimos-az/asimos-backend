# Asimos Backend (Render + Supabase)

## Local run
```bash
cp .env.example .env
npm install
npm run dev
```

## Render config
Create a Web Service (Node/Express). Set:
- Root Directory: `backend`
- Build Command: `npm install`
- Start Command: `npm start`

Environment Variables (Render Dashboard):
- SUPABASE_URL
- SUPABASE_ANON_KEY
- SUPABASE_SERVICE_ROLE_KEY

Admin Panel env:
- ADMIN_EMAIL (default: admin@asimos.local)
- ADMIN_PASSWORD (default: admin1234)
- ADMIN_JWT_SECRET (required in prod)
- ADMIN_TOKEN_TTL_SEC (optional)

> `SUPABASE_SERVICE_ROLE_KEY` is **server-only**. Never put it in mobile.

## Supabase migrations
Run `supabase_migrations.sql` in Supabase SQL editor. It adds:
- `profiles.expo_push_token` (optional)
- `public.events` table (admin activity feed)

## Geo
- `GET /geo/search?q=...` — Azerbaijan geocode proxy (Nominatim).

## Refresh token
- `POST /auth/refresh` body: `{ refreshToken }` -> returns new `{ token, refreshToken, user }`.

## Admin API
- `POST /admin/login` -> `{ token }`
- `GET /admin/dashboard`
- `GET /admin/users`
- `PATCH /admin/users/:id`
- `DELETE /admin/users/:id`
- `GET /admin/jobs`
- `PATCH /admin/jobs/:id`
- `DELETE /admin/jobs/:id`
- `GET /admin/events`
