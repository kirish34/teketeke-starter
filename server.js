// server.js — TekeTeke Starter (Matatus + Tills + USSD + Success Counts)
// USSD code format: ABCX (A,B,C are 3-digit base 001–999; X = digital root of A+B+C)
// Examples: 0011, 0022, 1236 (1+2+3=6), 9999 (9+9+9=27 -> 2+7=9)

require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const { createClient } = require('@supabase/supabase-js');

// ---- Env ----
const {
  PORT = 5001,
  NODE_ENV = 'development',
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE,
  USSD_ROOT = '123', // results in *123*<ussd_code># for display/return
  ALLOWED_ORIGINS = '',
  CALLBACK_SECRET,
  SESSION_SECRET
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
  console.warn('[WARN] Ensure SUPABASE_URL and SUPABASE_SERVICE_ROLE are set in environment');
}
if (!SESSION_SECRET || !(process.env.ADMIN_USER && process.env.ADMIN_PASSWORD)) {
  console.warn('[WARN] Configure SESSION_SECRET, ADMIN_USER and ADMIN_PASSWORD for admin login');
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
  auth: { autoRefreshToken: false, persistSession: false }
});

const app = express();
app.set('trust proxy', true);
app.use(helmet());

// CORS restriction: allow list in production; permissive in dev if unset
const allowed = (ALLOWED_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const corsOptions = {
  methods: ['GET', 'POST', 'OPTIONS'],
  origin: (origin, cb) => {
    // Same-origin or non-browser requests have no origin; allow them
    if (!origin) return cb(null, true);
    if (allowed.length === 0) return cb(null, NODE_ENV !== 'production');
    return cb(null, allowed.includes(origin));
  }
};
app.use(cors(corsOptions));

app.use(compression());

// Capture raw body for HMAC verification on callbacks
app.use(
  express.json({
    limit: '100kb',
    verify: (req, res, buf) => {
      try {
        req.rawBody = buf.toString('utf8');
      } catch (_) {
        req.rawBody = '';
      }
    }
  })
);
app.use(morgan(NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.static(path.join(__dirname, 'public')));

// ---- Admin gate helpers ----
function parseCookies(req) {
  const header = req.headers['cookie'] || '';
  const out = {};
  header.split(';').forEach((kv) => {
    const i = kv.indexOf('=');
    if (i > -1) {
      const k = kv.slice(0, i).trim();
      const v = kv.slice(i + 1).trim();
      out[k] = decodeURIComponent(v);
    }
  });
  return out;
}

function b64url(input) {
  return Buffer.from(input).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlJson(obj) {
  return b64url(JSON.stringify(obj));
}
function unb64url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString('utf8');
}

function signSession(payload) {
  const secret = SESSION_SECRET || 'changeme';
  const header = { alg: 'HS256', typ: 'JWT' };
  const encHeader = b64urlJson(header);
  const encPayload = b64urlJson(payload);
  const toSign = `${encHeader}.${encPayload}`;
  const sig = crypto
    .createHmac('sha256', secret)
    .update(toSign)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${toSign}.${sig}`;
}

function verifySession(token) {
  try {
    const secret = SESSION_SECRET || 'changeme';
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const [h, p, s] = parts;
    const recomputed = crypto
      .createHmac('sha256', secret)
      .update(`${h}.${p}`)
      .digest('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
    const a = Buffer.from(s);
    const b = Buffer.from(recomputed);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(unb64url(p));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

function getSession(req) {
  const cookies = parseCookies(req);
  const token = cookies['tt_sess'];
  const payload = verifySession(token);
  return payload && payload.user ? payload : null;
}

function requireAdmin(req, res, next) {
  const sess = getSession(req);
  if (sess && sess.user) return next();
  return res.status(401).json({ error: 'unauthorized' });
}

// ---- Helpers ----
const asApi = (fn) => async (req, res) => {
  try {
    const data = await fn(req, res);
    if (!res.headersSent) res.json(data);
  } catch (err) {
    console.error(err);
    if (!res.headersSent) res.status(500).json({ error: err.message || 'internal_error' });
  }
};

function digitalRootOfSumDigits(base3) {
  // base3 is "001".."999"
  const a = Number(base3[0]),
    b = Number(base3[1]),
    c = Number(base3[2]);
  const s = a + b + c;
  // digital root 1..9 (since base3 != "000")
  const dr = s % 9 === 0 ? 9 : s % 9;
  return String(dr);
}

function buildCodeFromBase(base3) {
  return base3 + digitalRootOfSumDigits(base3);
}

function isValidUssdCode4(code) {
  if (typeof code !== 'string' || code.length !== 4 || !/^\d{4}$/.test(code)) return false;
  const base = code.slice(0, 3);
  const check = code[3];
  return buildCodeFromBase(base)[3] === check;
}

// Normalize MSISDN to Kenyan E.164 without '+' (e.g., 2547xxxxxxx or 2541xxxxxxx)
function normalizeMsisdn(v) {
  if (v == null) return null;
  let s = String(v).trim();
  s = s.replace(/\D+/g, '');
  if (s.startsWith('0') && s.length === 10) return '254' + s.slice(1);
  if (s.startsWith('254') && s.length === 12) return s;
  if (s.length === 9 && (s.startsWith('7') || s.startsWith('1'))) return '254' + s;
  return s;
}

// ---- Simple in-memory rate limiter ----
function createRateLimiter({ windowMs, max, keyGenerator }) {
  const store = new Map();
  return function rateLimiter(req, res, next) {
    const now = Date.now();
    const key = keyGenerator(req);
    let entry = store.get(key);
    if (!entry || now - entry.start > windowMs) {
      entry = { start: now, count: 0 };
      store.set(key, entry);
    }
    entry.count += 1;
    if (entry.count > max) {
      const retryAfter = Math.max(1, Math.ceil((entry.start + windowMs - now) / 1000));
      res.set('Retry-After', String(retryAfter));
      return res.status(429).json({ error: 'rate_limited' });
    }
    next();
  };
}

const adminLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 300,
  keyGenerator: (req) => `${req.ip}|${(getSession(req) && getSession(req).user && getSession(req).user.name) || ''}`
});

const callbackLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 60,
  keyGenerator: (req) => req.ip
});

const loginLimiter = createRateLimiter({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20,
  keyGenerator: (req) => req.ip
});

// ---- Callback signature verification ----
function verifyCallbackSignature(req) {
  try {
    if (!CALLBACK_SECRET) return false;
    const provided = String(req.headers['x-callback-signature'] || '');
    if (!provided) return false;
    const computed = crypto.createHmac('sha256', CALLBACK_SECRET).update(req.rawBody || '').digest('hex');
    const a = Buffer.from(provided, 'hex');
    const b = Buffer.from(computed, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch (_) {
    return false;
  }
}

function requireCallbackSignature(req, res, next) {
  if (!CALLBACK_SECRET) return res.status(500).json({ error: 'callback_not_configured' });
  if (!verifyCallbackSignature(req)) return res.status(401).json({ error: 'invalid_signature' });
  next();
}

// Apply admin rate limiting to admin route prefixes
app.use(['/api/matatus', '/api/ussd', '/api/sim'], adminLimiter);

// ---- Health ----
app.get('/ping', (req, res) => res.json({ ok: true }));
app.get('/__version', (req, res) => res.json({ name: 'teketeke-starter', version: '0.4.0' }));

// ---- Public config ----
app.get('/api/config', (req, res) => {
  res.json({ ussd_root: USSD_ROOT });
});

// ---- Auth ----
app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const u = (process.env.ADMIN_USER || '').trim();
  const p = (process.env.ADMIN_PASSWORD || '').trim();
  if (!u || !p) return res.status(500).json({ error: 'admin_not_configured' });
  const ok = username === u && password === p;
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
  const exp = Math.floor(Date.now() / 1000) + 8 * 60 * 60; // 8h
  const token = signSession({ user: { name: u }, exp });
  const isProd = NODE_ENV === 'production';
  res.setHeader(
    'Set-Cookie',
    `tt_sess=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax${isProd ? '; Secure' : ''}`
  );
  return res.json({ ok: true, user: { name: u } });
});

app.post('/api/auth/logout', (req, res) => {
  const isProd = NODE_ENV === 'production';
  res.setHeader(
    'Set-Cookie',
    `tt_sess=; HttpOnly; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax${
      isProd ? '; Secure' : ''
    }`
  );
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  const sess = getSession(req);
  if (!sess) return res.status(401).json({ error: 'unauthorized' });
  res.json({ user: sess.user });
});

// ---- Admin APIs ----
app.post(
  '/api/matatus',
  requireAdmin,
  asApi(async (req) => {
    const { plate, name, sacco_name } = req.body || {};
    if (!plate) throw new Error('plate is required');
    const payload = {
      plate: String(plate).trim().toUpperCase(),
      name: name || null,
      sacco_name: sacco_name || null
    };
    const { data, error } = await supabase.from('matatus').upsert(payload, { onConflict: 'plate' }).select('*')
      .maybeSingle();
    if (error) throw error;
    return { matatu: data };
  })
);

app.post(
  '/api/matatus/:id/till',
  requireAdmin,
  asApi(async (req) => {
    const { id } = req.params;
    const { till_number } = req.body || {};
    if (!till_number) throw new Error('till_number is required');
    const { data, error } = await supabase
      .from('matatus')
      .update({ till_number: String(till_number).trim() })
      .eq('id', id)
      .select('*')
      .maybeSingle();
    if (error) throw error;
    return { matatu: data };
  })
);

// Allocate USSD code to a matatu (transactional via RPC assign_ussd_code)
app.post(
  '/api/matatus/:id/ussd',
  requireAdmin,
  asApi(async (req) => {
    const { id } = req.params;
    const { data: code, error } = await supabase.rpc('assign_ussd_code', { p_matatu_id: id });
    if (error) throw error;
    const dial = `*${USSD_ROOT}*${code}#`;
    const { data: mat, error: e2 } = await supabase
      .from('v_matatu_stats')
      .select('*')
      .eq('matatu_id', id)
      .maybeSingle();
    if (e2) throw e2;
    return { matatu: mat, dial };
  })
);

app.post(
  '/api/matatus/:id/ussd/reassign',
  requireAdmin,
  asApi(async (req) => {
    const { id } = req.params;
    const { data: current, error: currentErr } = await supabase
      .from('matatus')
      .select('ussd_code')
      .eq('id', id)
      .maybeSingle();
    if (currentErr) throw currentErr;
    if (!current) throw new Error('Matatu not found');

    const nowIso = new Date().toISOString();

    if (current.ussd_code) {
      await supabase
        .from('ussd_codes')
        .update({ status: 'free', assigned_to: null, assigned_at: null })
        .eq('code', current.ussd_code);
    }

    let freeQuery = supabase
      .from('ussd_codes')
      .select('code')
      .eq('status', 'free')
      .order('base', { ascending: true })
      .limit(1);

    if (current.ussd_code) {
      freeQuery = freeQuery.neq('code', current.ussd_code);
    }

    const { data: next, error: nextErr } = await freeQuery.maybeSingle();
    if (nextErr) throw nextErr;
    if (!next) throw new Error('No free USSD codes available');

    const { error: updateMatatuErr } = await supabase.from('matatus').update({ ussd_code: next.code }).eq('id', id);
    if (updateMatatuErr) throw updateMatatuErr;

    const { error: updatePoolErr } = await supabase
      .from('ussd_codes')
      .update({ status: 'assigned', assigned_to: id, assigned_at: nowIso })
      .eq('code', next.code);
    if (updatePoolErr) throw updatePoolErr;

    const { data: mat, error: viewErr } = await supabase
      .from('v_matatu_stats')
      .select('*')
      .eq('matatu_id', id)
      .maybeSingle();
    if (viewErr) throw viewErr;

    return { matatu: mat, dial: `*${USSD_ROOT}*${next.code}#` };
  })
);

app.get(
  '/api/ussd/validate/:code',
  requireAdmin,
  asApi(async (req) => {
    const { code } = req.params;
    const valid = isValidUssdCode4(code);
    const base = /^\d{4}$/.test(code) ? code.slice(0, 3) : null;
    return { code, base, valid, expected: base ? buildCodeFromBase(base) : null };
  })
);

app.get(
  '/api/matatus',
  requireAdmin,
  asApi(async () => {
    const { data, error } = await supabase.from('v_matatu_stats').select('*').order('last_tx_at', { ascending: false });
    if (error) throw error;
    return { items: data };
  })
);

app.get(
  '/api/matatus/:id',
  requireAdmin,
  asApi(async (req) => {
    const { id } = req.params;
    const { data, error } = await supabase.from('v_matatu_stats').select('*').eq('matatu_id', id).maybeSingle();
    if (error) throw error;
    return { matatu: data };
  })
);

app.get(
  '/api/transactions',
  requireAdmin,
  asApi(async (req) => {
    const { matatu_id, plate, status, limit } = req.query || {};
    const parsedLimit = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200);
    const normalizedStatus = typeof status === 'string' ? status.trim().toLowerCase() : '';
    const normalizedPlate = typeof plate === 'string' ? plate.trim() : '';
    const allowedStatuses = ['pending', 'success', 'failed', 'timeout'];
    if (normalizedStatus && !allowedStatuses.includes(normalizedStatus)) {
      throw new Error('Invalid status filter');
    }
    const selectColumns = `
      id,
      matatu_id,
      amount,
      msisdn,
      status,
      mpesa_receipt,
      gateway_ref,
      created_at,
      matatus:matatu_id (
        plate,
        till_number,
        name
      )
    `;

    let query = supabase.from('transactions').select(selectColumns).order('created_at', { ascending: false }).limit(parsedLimit);

    if (matatu_id) query = query.eq('matatu_id', matatu_id);
    if (normalizedStatus) query = query.eq('status', normalizedStatus);
    if (normalizedPlate) query = query.ilike('matatus.plate', `%${normalizedPlate}%`);

    const { data, error } = await query;
    if (error) throw error;

    const items = (data || []).map((row) => ({
      id: row.id,
      matatu_id: row.matatu_id,
      amount: Number(row.amount || 0),
      msisdn: row.msisdn || null,
      status: row.status,
      mpesa_receipt: row.mpesa_receipt || null,
      gateway_ref: row.gateway_ref || null,
      created_at: row.created_at,
      matatu: row.matatus ? { plate: row.matatus.plate || null, till_number: row.matatus.till_number || null, name: row.matatus.name || null } : null
    }));

    return { items };
  })
);

app.post(
  '/api/mpesa/callback',
  callbackLimiter,
  requireCallbackSignature,
  asApi(async (req) => {
    const { matatu_id, amount, msisdn, status, mpesa_receipt, gateway_ref, raw } = req.body || {};
    if (!matatu_id || typeof amount === 'undefined' || !status)
      throw new Error('matatu_id, amount, status are required');
    const amt = Number(amount);
    if (!(amt > 0)) throw new Error('amount must be > 0');
    const rec = {
      matatu_id,
      amount: amt,
      msisdn: normalizeMsisdn(msisdn),
      status: String(status).toLowerCase(),
      mpesa_receipt: mpesa_receipt || null,
      gateway_ref: gateway_ref || null,
      raw: raw || null
    };
    const { data, error } = await supabase.from('transactions').insert(rec).select('*').maybeSingle();
    if (error) throw error;
    return { saved: true, tx: data };
  })
);

app.post(
  '/api/sim/tx',
  requireAdmin,
  asApi(async (req) => {
    const { matatu_id, amount = 50, msisdn = '254700000000', success = true } = req.body || {};
    if (!matatu_id) throw new Error('matatu_id is required');
    const amt = Number(amount);
    if (!(amt > 0)) throw new Error('amount must be > 0');
    const { data, error } = await supabase
      .from('transactions')
      .insert({
        matatu_id,
        amount: amt,
        msisdn: normalizeMsisdn(msisdn),
        status: success ? 'success' : 'failed',
        mpesa_receipt: success ? 'TEST' + Math.floor(Math.random() * 1e6) : null,
        gateway_ref: 'SIM-' + Date.now()
      })
      .select('*')
      .maybeSingle();
    if (error) throw error;
    return { simulated: true, tx: data };
  })
);

app.delete(
  '/api/matatus/:id',
  requireAdmin,
  asApi(async (req) => {
    const { id } = req.params;
    const { data: current, error: currentErr } = await supabase
      .from('matatus')
      .select('ussd_code')
      .eq('id', id)
      .maybeSingle();
    if (currentErr) throw currentErr;
    if (!current) return { deleted: false };

    if (current.ussd_code) {
      await supabase
        .from('ussd_codes')
        .update({ status: 'free', assigned_to: null, assigned_at: null })
        .eq('code', current.ussd_code);
    }

    const { error: deleteErr } = await supabase.from('matatus').delete().eq('id', id);
    if (deleteErr) throw deleteErr;

    return { deleted: true };
  })
);

// ---- UI routes ----
function serveAdmin(req, res) {
  const sess = getSession(req);
  if (!sess) return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
}

app.get('/', serveAdmin);
// Support Vercel rewrite to /api/index for root
app.get('/api/index', serveAdmin);

// Login page with redirect when already authenticated
function serveLogin(req, res) {
  const sess = getSession(req);
  if (sess) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
}
app.get(['/login', '/login.html', '/api/login'], serveLogin);

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[teketeke] listening on http://localhost:${PORT}`);
  });
} else {
  module.exports = app;
}
