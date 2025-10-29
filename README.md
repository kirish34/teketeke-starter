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
- Run: `npm run dev`
- Open `http://localhost:5001` (admin UI)

3) Deploy to Vercel
- Push this repository to your VCS.
- Import into Vercel.
- Add the Environment Variables below in Vercel Project Settings.
- Deploy. Vercel serves `/public/admin.html` at `/` and all API under `/api/*` via `api/index.js`.

## Environment Variables (paste your credentials)

Paste values either in `.env` (local) or the Vercel dashboard (Production/Preview/Development). Do NOT commit real secrets.

- `SUPABASE_URL` — Your Supabase project URL (e.g., `https://xxxxx.supabase.co`).
- `SUPABASE_SERVICE_ROLE` — Service role key from Supabase (server-side only).
// Session-based admin auth only; no admin token header.
- `ADMIN_USER` — Admin username for login.
- `ADMIN_PASSWORD` — Admin password for login.
- `SESSION_SECRET` — Secret to sign admin session cookie.
- `ALLOWED_ORIGINS` — Comma-separated list of allowed origins (e.g., `https://your-admin.vercel.app,https://ops.example.com`).
- `USSD_ROOT` – The USSD root code prefix shown to users (default `123`).
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

- `GET /api/config` — Returns `{ ussd_root }` for the UI.
- Auth
  - `POST /api/auth/login` — Body `{ username, password }`, sets HTTP-only session cookie on success.
  - `POST /api/auth/logout` — Clears session cookie.
  - `GET /api/auth/me` — Returns current session.
- Admin (requires logged-in session):
  - `POST /api/matatus` — Create/Upsert matatu by `plate`.
  - `POST /api/matatus/:id/till` — Set till number.
  - `POST /api/matatus/:id/ussd` — Allocate next USSD.
  - `GET /api/matatus` — List with success counts.
- `GET /api/matatus/:id` – Single summary.
- `GET /api/ussd/validate/:code` – Validate a code.
- `POST /api/sim/tx` – Simulate a successful transaction.
- `POST /ussd` – Public USSD webhook entry point (expects Safaricom/aggregator payloads; returns `CON/END` responses).
- `POST /api/mpesa/callback` – Ingest a transaction (requires `x-callback-signature`).

## Notes

- On Vercel, the Express app runs as a serverless function from `api/index.js` and uses the same code as local dev.
- Static admin UI is served from `public/` (Vercel rewrite `/ -> /public/admin.html`).
- Admin UI requires login: visit `/login.html`, then you will be redirected back to `/`.
- Rate limiting is in-memory. For multi-instance or high scale, use a shared store (e.g., Redis) and/or a robust limiter.
- Keep `SUPABASE_SERVICE_ROLE` strictly server-side; never expose it in client code.

## Troubleshooting

- 401 on admin API: Ensure you saved the token in the Admin UI and `ADMIN_TOKEN` matches server config.
- CORS issues: Add your Vercel domain to `ALLOWED_ORIGINS`.
- Callback rejected: Check `CALLBACK_SECRET` and ensure signature uses the exact raw request body.
