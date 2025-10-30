# TekeTeke Starter (Vercel + Supabase)

A minimal Express + Supabase starter to manage Matatus, tills, USSD codes, and track transactions. Ready for deployment on Vercel (serverless) and for local development. Supabase provides the database and view.

## Quick Start

1) Supabase
- Create a new project in Supabase.
- Open SQL editor and run `supabase/000_starter.sql` to create tables and view.
- Then run `supabase/010_codes_pool.sql` to seed the USSD codes pool and allocator RPC.
  - To rollback, you can run `supabase/011_codes_pool_rollback.sql`.

2) Local development
- Copy `.env.example` to `.env` and paste your credentials.
- Install dependencies: `npm install`
- Run the Supabase migrations against your local or remote project (`supabase/000_starter.sql`, then `010_codes_pool.sql`).
- Start the API/UI: `npm run dev`
- (Optional) Sanity check endpoints: `node scripts/smoke.js`
- Open `http://localhost:5001` (admin UI)

3) Deploy to Vercel
- Push this repository to your VCS.
- Import into Vercel.
- Add the Environment Variables below in Vercel Project Settings.
- Deploy. Vercel serves `/public/admin.html` at `/` and all API under `/api/*` via `api/index.js`.

## Environment Variables (paste your credentials)

Paste values either in `.env` (local) or the Vercel dashboard (Production/Preview/Development). Do NOT commit real secrets.

- `SUPABASE_URL` â€” Your Supabase project URL (e.g., `https://xxxxx.supabase.co`).
- `SUPABASE_SERVICE_ROLE` â€” Service role key from Supabase (server-side only).
// Session-based admin auth only; no admin token header.
- `ADMIN_USER` â€” Admin username for login.
- `ADMIN_PASSWORD` â€” Admin password for login.
- `SESSION_SECRET` â€” Secret to sign admin session cookie.
- `ALLOWED_ORIGINS` â€” Comma-separated list of allowed origins (e.g., `https://your-admin.vercel.app,https://ops.example.com`).
- `USSD_ROOT` â€“ The USSD root code prefix shown to users (default `123`).
- `CALLBACK_SECRET` - Shared secret used to HMAC-sign the raw JSON body for `/api/mpesa/callback`.
- `OPS_WEBHOOK_URL` - Slack (or similar) webhook URL for operational alerts.
- `USSD_GATEWAY_SECRET` - Shared HMAC secret for authenticating `/ussd` callbacks (if your provider signs calls).
- `RATE_LIMIT_USSD_MAX` - Requests per minute allowed from the USSD gateway (default `90`).
- `PORT` - Local dev port (default `5001`).
- `NODE_ENV` - `development` or `production`.

## M-Pesa Callback Authentication

- Compute header `x-callback-signature` as lowercase hex HMAC-SHA256 of the exact raw request body using `CALLBACK_SECRET`.
- Example pseudo-code:

```
const signature = crypto.createHmac('sha256', CALLBACK_SECRET)
  .update(rawBody)
  .digest('hex');
// send header 'x-callback-signature': signature
```

If signature is missing or invalid, the server returns `401`.

## Endpoints

- `GET /api/config` â€” Returns `{ ussd_root }` for the UI.
- Auth
  - `POST /api/auth/login` â€” Body `{ username, password }`, sets HTTP-only session cookie on success.
  - `POST /api/auth/logout` â€” Clears session cookie.
  - `GET /api/auth/me` â€” Returns current session.
- Admin (requires logged-in session):
  - `POST /api/matatus` â€” Create/Upsert matatu by `plate`.
  - `POST /api/matatus/:id/till` â€” Set till number.
  - `POST /api/matatus/:id/ussd` â€” Allocate next USSD.
- `GET /api/matatus` â€“ List with success counts.
- `GET /api/matatus/:id` â€“ Single summary.
- `GET /api/matatus/search?plate=KDA123A` â€“ Server-side search by plate (returns up to 20 matches).
- `GET /api/ussd/validate/:code` â€“ Validate a code.
- `POST /api/sim/tx` â€“ Simulate a successful transaction.
- `POST /ussd` â€“ Public USSD webhook entry point (expects Safaricom/aggregator payloads; returns `CON/END` responses).
- `POST /api/mpesa/callback` â€“ Ingest a transaction (requires `x-callback-signature`).

## Notes

- On Vercel, the Express app runs as a serverless function from `api/index.js` and uses the same code as local dev.
- Static admin UI is served from `public/` (Vercel rewrite `/ -> /public/admin.html`).
- Admin UI requires login: visit `/login.html`, then you will be redirected back to `/`.
- Rate limiting is in-memory. For multi-instance or high scale, wire the limiter to a shared store (e.g., Redis/Upstash) and tune `RATE_LIMIT_CALLBACK_MAX` / `RATE_LIMIT_USSD_MAX` in env.
- All API responses set an `X-Request-ID`; error payloads echo the value as `request_id`.
- Keep `SUPABASE_SERVICE_ROLE` strictly server-side; never expose it in client code.

## Troubleshooting

- 401 on admin API: Ensure you saved the token in the Admin UI and `ADMIN_TOKEN` matches server config.
- CORS issues: Add your Vercel domain to `ALLOWED_ORIGINS`.
- Callback rejected: Check `CALLBACK_SECRET` and ensure signature uses the exact raw request body.
