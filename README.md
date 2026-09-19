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

### Registration OTP delivery

Registration and resend use the same 60-second per-email cooldown. If `SMTP_HOST`,
`SMTP_USER`, `SMTP_PASS` and a sender (`SMTP_FROM`, falling back to `SMTP_USER`) are
configured, the backend generates a Supabase email OTP and sends a numeric code
through that SMTP provider. SMTP acceptance is required before reporting success;
provider rejection and timeouts return an error. Acceptance does not guarantee inbox delivery.

Without backend SMTP, delivery uses Supabase Auth's configured mail service. In
that mode, configure Custom SMTP in Supabase and include `{{ .Token }}` in the
Magic Link email template. Check sender/domain verification and provider logs if
messages are absent. Never log OTPs, auth links or SMTP credentials.

`phone` is required and `whatsapp` is optional; both accept Azerbaijani local and
international formats and are stored as `+994…`. An omitted/empty WhatsApp remains
null. The existing `profiles.phone` and `profiles.whatsapp` columns are used;
no database migration is needed.

Run registration regression checks with `node --test src/registration.test.js`.
The in-process cooldown resets on restart; use a shared rate limiter before
running multiple backend instances.

## Career articles

Run `supabase/migrations/20260919154428_career_articles.sql` after the existing
schema migrations. It creates `career_articles` and three editable starter
articles. The script is safe to rerun and does not overwrite existing articles.
RLS is enabled, and direct access is revoked from `anon` and `authenticated`;
all content is served through this backend using its server-only service role.

- `GET /career-articles?page=1&limit=12&q=CV&category=CV`: published summaries,
  total count, server-side search/pagination. Featured articles appear first.
- `GET /career-articles/:slug`: published article; drafts return 404.
- `GET /admin/career-articles`: admin listing, including drafts; optional `status`.
- `GET /admin/career-articles/:id`: full article for editing.
- `POST /admin/career-articles`: create; defaults to draft.
- `PUT /admin/career-articles/:id`: update the complete editable article.
- `DELETE /admin/career-articles/:id`: delete.

Every admin route requires the existing admin Bearer token. Editable fields:
`title`, `slug`, `excerpt`, `body`, `category`, `author`, `cover_url` (HTTPS or empty),
`cover_style` (`mint`, `peach`, `blue`, `lilac`), `featured`, `status` (`draft`,
`published`). Reading time is calculated automatically. Body content is plain
text with blank-line-separated paragraphs, `##` headings, `-` lists, and `>`
quotes; the website renders text safely without accepting raw HTML.

Run `npm test` for registration and career API checks. Career tests use an
in-memory database and an ephemeral localhost server, never production data.
