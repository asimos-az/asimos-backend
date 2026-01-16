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

> Service role key is **server-only**. Never put it in mobile.


## Geo
- `GET /geo/search?q=...` — Azerbaijan geocode proxy (Nominatim).


## Refresh token
- `POST /auth/refresh` body: `{ refreshToken }` -> returns new `{ token, refreshToken, user }`.
