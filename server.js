// server.js â€” TekeTeke Starter (Matatus + Tills + USSD + Success Counts)
// USSD code format: ABCX (A,B,C are 3-digit base 001â€“999; X = digital root of A+B+C)
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
const pkg = require('./package.json');

// ---- Env ----
const {
  PORT = 5001,
  NODE_ENV = 'development',
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE,
  USSD_ROOT = '123', // results in *123*<ussd_code># for display/return
  ALLOWED_ORIGINS = '',
  CALLBACK_SECRET,
  SESSION_SECRET,
  OPS_WEBHOOK_URL,
  RATE_LIMIT_CALLBACK_MAX = '60',
  RATE_LIMIT_CALLBACK_WINDOW_MS = String(60 * 1000),
  RATE_LIMIT_USSD_MAX = '90',
  HEALTHCHECK_SKIP_DB = 'false',
  USSD_GATEWAY_SECRET
} = process.env;
const APP_NAME = pkg.name || 'teketeke-starter';
const APP_VERSION = pkg.version || '0.0.0';
const CSP_DIRECTIVES = {
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'"],
  connectSrc: ["'self'"],
  imgSrc: ["'self'", 'data:'],
  styleSrc: ["'self'", "'unsafe-inline'"],
  fontSrc: ["'self'", 'data:'],
  baseUri: ["'self'"],
  formAction: ["'self'"],
  frameAncestors: ["'self'"]
};

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
  console.warn('[WARN] Ensure SUPABASE_URL and SUPABASE_SERVICE_ROLE are set in environment');
}
if (!SESSION_SECRET || !(process.env.ADMIN_USER && process.env.ADMIN_PASSWORD)) {
  console.warn('[WARN] Configure SESSION_SECRET, ADMIN_USER and ADMIN_PASSWORD for admin login');
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
  auth: { autoRefreshToken: false, persistSession: false }
});

function resolveSupabase(req) {
  return (req && req.app && req.app.locals && req.app.locals.supabase) || supabase;
}

async function notifyOps(event, payload = {}) {
  if (!OPS_WEBHOOK_URL) return;
  try {
    await fetch(OPS_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        event,
        app: APP_NAME,
        version: APP_VERSION,
        timestamp: new Date().toISOString(),
        payload
      })
    });
  } catch (err) {
    console.error('[notifyOps] failed', err);
  }
}

const app = express();
app.set('trust proxy', true);

const assignRequestId = (req, res, next) => {
  const header = typeof req.headers['x-request-id'] === 'string' ? req.headers['x-request-id'] : '';
  const sanitized = /^[A-Za-z0-9._-]{3,64}$/.test(header) ? header : crypto.randomUUID();
  req.requestId = sanitized;
  res.locals.requestId = sanitized;
  res.setHeader('X-Request-ID', sanitized);
  next();
};

morgan.token('id', (req) => req.requestId || '-');

const morganFormat =
  NODE_ENV === 'production'
    ? ':remote-addr - :remote-user [:date[iso]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" req_id=:id :response-time ms'
    : ':method :url :status req_id=:id - :response-time ms';

app.use(assignRequestId);
app.use(
  helmet({
    contentSecurityPolicy: { directives: CSP_DIRECTIVES },
    crossOriginEmbedderPolicy: false
  })
);

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

// keep the raw bytes for HMAC verification
app.use(
  express.json({
    type: 'application/json',
    limit: '1mb',
    verify: (req, res, buf) => {
      req.rawBody = buf.toString('utf8');
    }
  })
);
app.use(
  express.urlencoded({
    extended: false,
    limit: '1mb',
    verify: (req, res, buf) => {
      if (!req.rawBody && buf && buf.length) {
        req.rawBody = buf.toString('utf8');
      }
    }
  })
);
app.use(morgan(morganFormat));
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
  const requestId = req.requestId || null;
  try {
    const data = await fn(req, res);
    if (!res.headersSent) res.json(data);
  } catch (err) {
    console.error(err);
    const code = err && typeof err === 'object' ? err.code || err.status || err.statusCode : null;
    notifyOps('api_error', {
      path: req.originalUrl,
      method: req.method,
      code,
      message: err && err.message ? err.message : String(err),
      request_id: requestId
    });
    if (res.headersSent) return;
    if (code === '23505') {
      return res
        .status(409)
        .json({
          error: 'duplicate',
          message: err.message || 'duplicate key',
          details: err.details || null,
          request_id: requestId
        });
    }
    if (code === '23503') {
      return res
        .status(400)
        .json({
          error: 'invalid_reference',
          message: err.message || 'invalid reference',
          details: err.details || null,
          request_id: requestId
        });
    }
    if (typeof code === 'number' && code >= 400 && code < 600) {
      return res.status(code).json({ error: err.message || 'error', request_id: requestId });
    }
    res.status(500).json({ error: err.message || 'internal_error', request_id: requestId });
  }
};

const sendUssdResponse = (res, type, message) => {
  const sanitizedType = type === 'END' ? 'END' : 'CON';
  const text = `${sanitizedType} ${message || ''}`.trim();
  res.set('Content-Type', 'text/plain; charset=utf-8');
  res.status(200).send(text);
};

const asUssd = (fn) => async (req, res) => {
  const requestId = req.requestId || null;
  try {
    const payload = await fn(req, res);
    if (res.headersSent) return;
    if (!payload || typeof payload !== 'object') throw new Error('Invalid USSD payload');
    sendUssdResponse(res, payload.type, payload.message);
  } catch (err) {
    console.error('[ussd]', err);
    notifyOps('ussd_error', {
      path: req.originalUrl,
      method: req.method,
      message: err && err.message ? err.message : String(err),
      request_id: requestId
    });
    if (!res.headersSent) {
      sendUssdResponse(res, 'END', 'Service temporarily unavailable. Please try again later.');
    }
  }
};

function extractUssdPayload(req) {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const pick = (keys) => {
    for (const key of keys) {
      if (body[key] != null && body[key] !== '') return body[key];
    }
    return null;
  };
  const textValue = pick(['text', 'Text', 'userInput', 'input', 'message']) || '';
  return {
    sessionId: pick(['sessionId', 'session_id', 'SessionId', 'sessionID']),
    phoneNumber: pick(['phoneNumber', 'PhoneNumber', 'msisdn', 'Msisdn', 'MSISDN', 'phone']),
    serviceCode: pick(['serviceCode', 'service_code', 'ServiceCode']),
    operator: pick(['operator', 'Operator']),
    text: typeof textValue === 'string' ? textValue : ''
  };
}

function parseUssdSegments(text) {
  if (!text) return [];
  const raw = String(text);
  if (raw.trim() === '') return [];
  const parts = raw.split('*');
  while (parts.length && parts[parts.length - 1] === '') {
    parts.pop();
  }
  return parts;
}

function sanitizePlateInput(input) {
  if (input == null) return null;
  const raw = String(input).trim().toUpperCase();
  if (!raw) return null;
  const normalized = raw.replace(/[^A-Z0-9]/g, '');
  if (!normalized) return null;
  return { raw, normalized };
}

function createHttpError(message, status = 400, details = null) {
  const err = new Error(message);
  err.status = status;
  if (details) err.details = details;
  return err;
}

function ensureValidPlate(value) {
  const sanitized = sanitizePlateInput(value);
  if (!sanitized) throw createHttpError('invalid_plate', 400);
  if (!/^[A-Z]{3}\d{3}[A-Z]$/.test(sanitized.normalized)) throw createHttpError('invalid_plate', 400);
  return sanitized.raw.replace(/\s+/g, ' ').trim();
}

function ensureValidTill(value) {
  const trimmed = String(value || '').trim();
  if (!/^\d{4,12}$/.test(trimmed)) throw createHttpError('invalid_till', 400);
  return trimmed;
}

function formatUssdDate(iso) {
  if (!iso) return null;
  const dt = new Date(iso);
  if (Number.isNaN(dt.getTime())) return null;
  const day = dt.toLocaleDateString('en-KE', { day: '2-digit', month: '2-digit' });
  const time = dt.toLocaleTimeString('en-KE', { hour: '2-digit', minute: '2-digit', hour12: false });
  return `${day} ${time}`;
}

async function lookupMatatuSummary(plateInput, supabaseClient) {
  const sanitized = sanitizePlateInput(plateInput);
  if (!sanitized) {
    return { ok: false, reason: 'invalid' };
  }
  const columns = 'matatu_id, plate, till_number, ussd_code, total_success, total_failed, last_tx_at';
  const baseBuilder = supabaseClient
    .from('v_matatu_stats')
    .select(columns)
    .filter("replace(upper(plate),' ','')", 'eq', sanitized.normalized);
  const primary = await baseBuilder.maybeSingle();
  if (primary.error) throw primary.error;
  if (primary.data) {
    return { ok: true, matatu: primary.data, sanitized };
  }

  const wildcard = `%${sanitized.normalized.split('').join('%')}%`;
  const fallbackBuilder = supabaseClient.from('v_matatu_stats').select(columns).ilike('plate', wildcard).limit(1);
  const fallback = await fallbackBuilder.maybeSingle();
  if (fallback.error) throw fallback.error;
  if (fallback.data) {
    return { ok: true, matatu: fallback.data, sanitized };
  }
  return { ok: false, reason: 'not_found', sanitized };
}

const USSD_ROOT_MESSAGE = [
  'Karibu TekeTeke.',
  '1. Angalia matatu.',
  '2. Msaada.',
  '0. Ondoka.'
].join('\n');

const USSD_SUPPORT_MESSAGE = 'Msaada: piga 0800-123-456 au barua support@teketeke.dev';

async function handleUssdFlow(payload, supabaseClient, context = {}) {
  const segments = parseUssdSegments(payload.text);
  const action = segments[0] || '';
  if (!action) {
    return { type: 'CON', message: USSD_ROOT_MESSAGE };
  }

  if (action === '0') {
    return { type: 'END', message: 'Asante kwa kutumia TekeTeke.' };
  }

  if (action === '2') {
    return { type: 'END', message: USSD_SUPPORT_MESSAGE };
  }

  if (action === '1') {
    if (segments.length === 1) {
      return { type: 'CON', message: 'Ingiza nambari ya plate (mfano KDA123A).' };
    }
    const lookup = await lookupMatatuSummary(segments[1], supabaseClient);
    if (lookup.ok && lookup.matatu) {
      const m = lookup.matatu;
      const dial = m.ussd_code ? `*${USSD_ROOT}*${m.ussd_code}#` : 'haijatengwa';
      const successCount = Number(m.total_success || 0);
      const successDisplay = Number.isFinite(successCount) ? successCount.toLocaleString('en-KE') : '0';
      const lines = [
        m.plate || lookup.sanitized.raw,
        `Till: ${m.till_number || 'haijawekwa'}`,
        `USSD: ${dial}`,
        `Mafanikio: ${successDisplay}`
      ];
      const lastTx = formatUssdDate(m.last_tx_at);
      if (lastTx) lines.push(`Last tx: ${lastTx}`);
      notifyOps('ussd_lookup', {
        plate: lookup.sanitized.normalized,
        found: true,
        msisdn_suffix: payload.phoneNumber ? String(payload.phoneNumber).slice(-4) : null,
        request_id: context.requestId || null
      });
      return { type: 'END', message: lines.join('\n') };
    }
    if (lookup.reason === 'invalid') {
      return { type: 'CON', message: 'Plate si sahihi. Tafadhali jaribu tena:' };
    }
    notifyOps('ussd_lookup', {
      plate: lookup.sanitized ? lookup.sanitized.normalized : null,
      found: false,
      msisdn_suffix: payload.phoneNumber ? String(payload.phoneNumber).slice(-4) : null,
      request_id: context.requestId || null
    });
    return { type: 'END', message: 'Hatukupata matatu hiyo. Hakikisha plate ni sahihi.' };
  }

  return {
    type: 'CON',
    message: ['Chaguo si sahihi.', '1. Angalia matatu.', '2. Msaada.', '0. Ondoka.'].join('\n')
  };
}

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

function parseRangeDate(value, endOfDay = false) {
  if (!value) return null;
  let str = String(value).trim();
  if (!str) return null;
  if (!str.includes('T')) {
    str = `${str}${endOfDay ? 'T23:59:59.999' : 'T00:00:00'}`;
  }
  const parsed = new Date(str);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function getTodayBounds() {
  const now = new Date();
  const start = new Date(now);
  start.setHours(0, 0, 0, 0);
  const end = new Date(now);
  end.setHours(23, 59, 59, 999);
  return { start: start.toISOString(), end: end.toISOString() };
}

// ---- Simple in-memory rate limiter ----
function createRateLimiter({ windowMs, max, keyGenerator, name = 'rateLimiter' }) {
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
      notifyOps('rate_limited', {
        limiter: name,
        key,
        retry_after: retryAfter,
        ip: req.ip,
        path: req.originalUrl,
        request_id: req.requestId || null
      });
      return res.status(429).json({ error: 'rate_limited', request_id: req.requestId || null });
    }
    next();
  };
}

const ussdLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: Number(RATE_LIMIT_USSD_MAX) || 90,
  keyGenerator: (req) => {
    const body = req.body || {};
    const key =
      body.phoneNumber ||
      body.PhoneNumber ||
      body.msisdn ||
      body.Msisdn ||
      body.sessionId ||
      body.session_id;
    return key || req.ip;
  },
  name: 'ussd'
});

const adminLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 300,
  keyGenerator: (req) => `${req.ip}|${(getSession(req) && getSession(req).user && getSession(req).user.name) || ''}`
});

const callbackLimiter = createRateLimiter({
  windowMs: Number(RATE_LIMIT_CALLBACK_WINDOW_MS) || 60 * 1000,
  max: Number(RATE_LIMIT_CALLBACK_MAX) || 60,
  keyGenerator: (req) => req.ip,
  name: 'callback'
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

function verifyUssdSignature(req) {
  if (!USSD_GATEWAY_SECRET) return true;
  try {
    const provided = String(req.headers['x-ussd-signature'] || '');
    if (!provided) return false;
    const raw =
      typeof req.rawBody === 'string'
        ? req.rawBody
        : JSON.stringify(req.body && typeof req.body === 'object' ? req.body : {});
    const computed = crypto.createHmac('sha256', USSD_GATEWAY_SECRET).update(raw).digest('hex');
    let providedBuf;
    try {
      providedBuf = Buffer.from(provided, 'hex');
    } catch (_) {
      providedBuf = Buffer.from(provided, 'utf8');
    }
    const computedBuf = Buffer.from(computed, 'hex');
    if (providedBuf.length !== computedBuf.length) return false;
    return crypto.timingSafeEqual(providedBuf, computedBuf);
  } catch (_) {
    return false;
  }
}

function requireUssdSignature(req, res, next) {
  if (!USSD_GATEWAY_SECRET) return next();
  if (verifyUssdSignature(req)) return next();
  notifyOps('ussd_signature_invalid', {
    path: req.originalUrl,
    session: req.body && (req.body.sessionId || req.body.session_id),
    msisdn_suffix: req.body && req.body.phoneNumber ? String(req.body.phoneNumber).slice(-4) : null,
    request_id: req.requestId || null
  });
  if (!res.headersSent) {
    sendUssdResponse(res, 'END', 'Huduma haikupatikana. (usumbufu wa uhalalishaji)');
  }
}

// Apply admin rate limiting to admin route prefixes
app.use(['/api/matatus', '/api/ussd', '/api/sim'], adminLimiter);

app.post(
  '/ussd',
  ussdLimiter,
  requireUssdSignature,
  asUssd(async (req) => {
    const payload = extractUssdPayload(req);
    const supabaseClient = (req.app && req.app.locals && req.app.locals.supabase) || supabase;
    return handleUssdFlow(payload, supabaseClient, { requestId: req.requestId || null });
  })
);

// ---- Health ----
app.get('/ping', (req, res) => res.json({ ok: true }));
app.get('/__version', (req, res) => res.json({ name: APP_NAME, version: APP_VERSION }));

app.get('/healthz', async (req, res) => {
  const started = Date.now();
  const result = {
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    version: APP_VERSION,
    checks: {}
  };
  let statusCode = 200;

  if (HEALTHCHECK_SKIP_DB === 'true' || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
    result.checks.supabase = { status: 'skipped' };
  } else {
    const dbStart = Date.now();
    try {
      const supabaseClient = resolveSupabase(req);
      const { error } = await supabaseClient.from('transactions').select('id', { head: true }).limit(1);
      if (error) throw error;
      result.checks.supabase = { status: 'ok', latency_ms: Date.now() - dbStart };
    } catch (err) {
      statusCode = 503;
      result.status = 'degraded';
      result.checks.supabase = { status: 'error', latency_ms: Date.now() - dbStart, error: err.message };
      notifyOps('healthcheck_supabase_error', { message: err.message, request_id: req.requestId || null });
    }
  }

  result.duration_ms = Date.now() - started;
  res.status(statusCode).json(result);
});

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
    const supabaseClient = resolveSupabase(req);
    const { plate, name, sacco_name } = req.body || {};
    if (!plate) throw createHttpError('plate_required', 400);
    const safePlate = ensureValidPlate(plate);
    const payload = {
      plate: safePlate,
      name: name ? String(name).trim() || null : null,
      sacco_name: sacco_name ? String(sacco_name).trim() || null : null
    };
    const { data, error } = await supabaseClient
      .from('matatus')
      .upsert(payload, { onConflict: 'plate' })
      .select('*')
      .maybeSingle();
    if (error) throw error;
    return { matatu: data };
  })
);

app.post(
  '/api/matatus/:id/till',
  requireAdmin,
  asApi(async (req) => {
    const supabaseClient = resolveSupabase(req);
    const { id } = req.params;
    const { till_number } = req.body || {};
    if (!till_number) throw createHttpError('till_required', 400);
    const safeTill = ensureValidTill(till_number);
    const { data, error } = await supabaseClient
      .from('matatus')
      .update({ till_number: safeTill })
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
    const supabaseClient = resolveSupabase(req);
    const { id } = req.params;
    const { data: code, error } = await supabaseClient.rpc('assign_ussd_code', { p_matatu_id: id });
    if (error) throw error;
    const dial = `*${USSD_ROOT}*${code}#`;
    const { data: mat, error: e2 } = await supabaseClient
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
    const supabaseClient = resolveSupabase(req);
    const { id } = req.params;
    const { data: current, error: currentErr } = await supabaseClient
      .from('matatus')
      .select('ussd_code')
      .eq('id', id)
      .maybeSingle();
    if (currentErr) throw currentErr;
    if (!current) throw new Error('Matatu not found');

    const nowIso = new Date().toISOString();

    if (current.ussd_code) {
      await supabaseClient
        .from('ussd_codes')
        .update({ status: 'free', assigned_to: null, assigned_at: null })
        .eq('code', current.ussd_code);
    }

    let freeQuery = supabaseClient
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

    const { error: updateMatatuErr } = await supabaseClient.from('matatus').update({ ussd_code: next.code }).eq('id', id);
    if (updateMatatuErr) throw updateMatatuErr;

    const { error: updatePoolErr } = await supabaseClient
      .from('ussd_codes')
      .update({ status: 'assigned', assigned_to: id, assigned_at: nowIso })
      .eq('code', next.code);
    if (updatePoolErr) throw updatePoolErr;

    const { data: mat, error: viewErr } = await supabaseClient
      .from('v_matatu_stats')
      .select('*')
      .eq('matatu_id', id)
      .maybeSingle();
    if (viewErr) throw viewErr;

    return { matatu: mat, dial: `*${USSD_ROOT}*${next.code}#` };
  })
);

app.get(
  '/api/matatus/search',
  requireAdmin,
  asApi(async (req) => {
    const plateQuery = (req.query && req.query.plate) || '';
    const query = String(plateQuery || '').trim();
    if (!query) return { items: [], meta: { total: 0, query: '' } };

    const supabaseClient = resolveSupabase(req);
    const sanitized = sanitizePlateInput(query);
    const results = [];
    const seen = new Set();

    if (sanitized && /^[A-Z]{3}\d{3}[A-Z]$/.test(sanitized.normalized)) {
      const exactPlate = sanitized.raw.replace(/\s+/g, ' ').trim();
      const { data: exact, error: exactErr } = await supabaseClient
        .from('v_matatu_stats')
        .select('*')
        .eq('plate', exactPlate)
        .maybeSingle();
      if (exactErr) throw exactErr;
      if (exact) {
        results.push(exact);
        if (exact.matatu_id) seen.add(exact.matatu_id);
      }
    }

    const pattern = `%${query.replace(/\s+/g, '%')}%`;
    const remaining = Math.max(0, 20 - results.length);
    if (remaining > 0) {
      const { data: fuzzy, error: fuzzyErr } = await supabaseClient
        .from('v_matatu_stats')
        .select('*')
        .ilike('plate', pattern)
        .order('plate', { ascending: true })
        .limit(remaining);
      if (fuzzyErr) throw fuzzyErr;
      (fuzzy || []).forEach((row) => {
        if (!row) return;
        if (row.matatu_id && seen.has(row.matatu_id)) return;
        results.push(row);
        if (row.matatu_id) seen.add(row.matatu_id);
      });
    }

    return { items: results, meta: { total: results.length, query } };
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
  asApi(async (req) => {
    const supabaseClient = resolveSupabase(req);
    const { data, error } = await supabaseClient
      .from('v_matatu_stats')
      .select('*')
      .order('last_tx_at', { ascending: false });
    if (error) throw error;
    const items = data || [];
    return { items, meta: { total: items.length } };
  })
);

app.get(
  '/api/matatus/:id',
  requireAdmin,
  asApi(async (req) => {
    const { id } = req.params;
    const supabaseClient = resolveSupabase(req);
    const { data, error } = await supabaseClient.from('v_matatu_stats').select('*').eq('matatu_id', id).maybeSingle();
    if (error) throw error;
    return { matatu: data };
  })
);

app.get(
  '/api/transactions',
  requireAdmin,
  asApi(async (req) => {
    const supabaseClient = resolveSupabase(req);
    const { matatu_id, plate, status, limit, from, to } = req.query || {};
    const parsedLimit = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200);
    const normalizedStatus = typeof status === 'string' ? status.trim().toLowerCase() : '';
    const normalizedPlate = typeof plate === 'string' ? plate.trim() : '';
    const allowedStatuses = ['pending', 'success', 'failed', 'timeout'];
    if (normalizedStatus && !allowedStatuses.includes(normalizedStatus)) {
      throw new Error('Invalid status filter');
    }

    const matatuIdsSet = new Set();
    if (matatu_id) matatuIdsSet.add(matatu_id);

    if (!matatu_id && normalizedPlate) {
      const { data: matched, error: matchErr } = await supabaseClient
        .from('matatus')
        .select('id')
        .ilike('plate', `%${normalizedPlate}%`)
        .limit(20);
      if (matchErr) throw matchErr;
      (matched || []).forEach((row) => {
        if (row && row.id) matatuIdsSet.add(row.id);
      });
      if (matatuIdsSet.size === 0) {
        return { items: [], summary: { total: 0, total_today: 0 } };
      }
    }

    const matatuIds = Array.from(matatuIdsSet);
    const fromIso = parseRangeDate(from, false);
    const toIso = parseRangeDate(to, true);
    const { start: todayStartIso, end: todayEndIso } = getTodayBounds();

    const applyFilters = (builder, opts = {}) => {
      const { dateFrom, dateTo } = opts;
      if (matatuIds.length === 1) {
        builder = builder.eq('matatu_id', matatuIds[0]);
      } else if (matatuIds.length > 1) {
        builder = builder.in('matatu_id', matatuIds);
      }
      if (normalizedStatus) builder = builder.eq('status', normalizedStatus);
      if (dateFrom) builder = builder.gte('created_at', dateFrom);
      if (dateTo) builder = builder.lte('created_at', dateTo);
      return builder;
    };

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

    const [dataRes, countRes, todayRes] = await Promise.all([
      applyFilters(
        supabaseClient
          .from('transactions')
          .select(selectColumns)
          .order('created_at', { ascending: false })
          .limit(parsedLimit),
        { dateFrom: fromIso, dateTo: toIso }
      ),
      applyFilters(
        supabaseClient.from('transactions').select('id', { count: 'exact', head: true }),
        { dateFrom: fromIso, dateTo: toIso }
      ),
      applyFilters(
        supabaseClient.from('transactions').select('id', { count: 'exact', head: true }),
        { dateFrom: todayStartIso, dateTo: todayEndIso }
      )
    ]);

    if (dataRes.error) throw dataRes.error;
    if (countRes.error) throw countRes.error;
    if (todayRes.error) throw todayRes.error;

    const items = (dataRes.data || []).map((row) => ({
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

    return {
      items,
      summary: {
        total: typeof countRes.count === 'number' ? countRes.count : 0,
        total_today: typeof todayRes.count === 'number' ? todayRes.count : 0
      }
    };
  })
);

app.post(
  '/api/mpesa/callback',
  callbackLimiter,
  requireCallbackSignature,
  asApi(async (req) => {
    const supabaseClient = resolveSupabase(req);
    const { matatu_id, amount, msisdn, status, mpesa_receipt, gateway_ref, raw } = req.body || {};
    if (!matatu_id || typeof amount === 'undefined' || !status)
      throw new Error('matatu_id, amount, status are required');
    const amt = Number(amount);
    if (!(amt > 0)) throw new Error('amount must be > 0');
    const normalizedStatus = String(status).toLowerCase();
    if (normalizedStatus !== 'success') {
      console.warn('[callback] Ignoring non-success transaction', {
        matatu_id,
        status: normalizedStatus,
        mpesa_receipt
      });
      return { saved: false, ignored: true };
    }
    const rec = {
      matatu_id,
      amount: amt,
      msisdn: normalizeMsisdn(msisdn),
      status: 'success',
      mpesa_receipt: mpesa_receipt || null,
      gateway_ref: gateway_ref || null,
      raw: raw || null
    };
    const { data, error } = await supabaseClient.from('transactions').insert(rec).select('*').maybeSingle();
    if (error) throw error;
    return { saved: true, tx: data };
  })
);

app.post(
  '/api/sim/tx',
  requireAdmin,
  asApi(async (req) => {
    const supabaseClient = resolveSupabase(req);
    const { matatu_id, amount = 50, msisdn = '254700000000' } = req.body || {};
    if (!matatu_id) throw new Error('matatu_id is required');
    const amt = Number(amount);
    if (!(amt > 0)) throw new Error('amount must be > 0');
    const { data, error } = await supabaseClient
      .from('transactions')
      .insert({
        matatu_id,
        amount: amt,
        msisdn: normalizeMsisdn(msisdn),
        status: 'success',
        mpesa_receipt: 'TEST' + Math.floor(Math.random() * 1e6),
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
    const supabaseClient = resolveSupabase(req);
    const { id } = req.params;
    const { data: current, error: currentErr } = await supabaseClient
      .from('matatus')
      .select('ussd_code')
      .eq('id', id)
      .maybeSingle();
    if (currentErr) throw currentErr;
    if (!current) return { deleted: false };

    if (current.ussd_code) {
      await supabaseClient
        .from('ussd_codes')
        .update({ status: 'free', assigned_to: null, assigned_at: null })
        .eq('code', current.ussd_code);
    }

    const { error: deleteErr } = await supabaseClient.from('matatus').delete().eq('id', id);
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

app.use((err, req, res, next) => {
  console.error('[unhandled]', err);
  notifyOps('unhandled_error', {
    path: req.originalUrl,
    method: req.method,
    message: err && err.message ? err.message : String(err),
    request_id: req.requestId || null
  });
  res.status(500).json({ error: 'internal_error', message: err.message, request_id: req.requestId || null });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[teketeke] listening on http://localhost:${PORT}`);
  });
}

module.exports = app;
module.exports.createRateLimiter = createRateLimiter;
module.exports.verifyCallbackSignature = verifyCallbackSignature;
module.exports.notifyOps = notifyOps;
module.exports.APP_VERSION = APP_VERSION;

