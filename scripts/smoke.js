/* Simple smoke test for admin endpoints.
 * - Starts the exported Express app locally on a test port
 * - Logs in with temporary admin creds
 * - Calls /ping, /api/config, /api/auth/me, /api/matatus
 */

// Ensure Node 18+ (for global fetch)
const assertNode18 = () => {
  const [major] = process.versions.node.split('.').map(Number);
  if (major < 18) {
    console.error('Node 18+ required');
    process.exit(1);
  }
};
assertNode18();

process.env.PORT = process.env.PORT || '5055';
process.env.ADMIN_USER = process.env.ADMIN_USER || 'admin';
process.env.ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password123!';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'smoke-secret-please-change';

const http = require('http');
// Use the Vercel handler which wraps the Express app
const handler = require('../api/index.js');

async function run() {
  console.log('Handler type:', typeof handler);
  const server = http.createServer(handler).listen(process.env.PORT, '127.0.0.1');
  await new Promise((resolve) => server.on('listening', resolve));
  const makeFetch = (url, opts={}) => {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 15000);
    const p = fetch(url, { ...opts, signal: controller.signal });
    return p.finally(() => clearTimeout(t));
  };
  const base = `http://127.0.0.1:${process.env.PORT}`;
  const results = [];
  let cookie = '';

  const record = (name, ok, info) => results.push({ name, ok, info });

  try {
    // /ping
    const r1 = await makeFetch(`${base}/ping`);
    const b1 = await r1.json().catch(() => ({}));
    record('GET /ping', r1.ok && b1.ok === true, { status: r1.status, body: b1 });

    // /api/config
    const r2 = await makeFetch(`${base}/api/config`);
    const b2 = await r2.json().catch(() => ({}));
    record('GET /api/config', r2.ok && 'ussd_root' in b2, { status: r2.status, body: b2 });

    // login
    const r3 = await makeFetch(`${base}/api/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: process.env.ADMIN_USER, password: process.env.ADMIN_PASSWORD })
    });
    const b3 = await r3.json().catch(() => ({}));
    const setCookie = r3.headers.get('set-cookie') || '';
    if (r3.ok && setCookie) cookie = setCookie.split(';')[0];
    record('POST /api/auth/login', r3.ok && !!cookie, { status: r3.status, body: b3 });

    // /api/auth/me
    const r4 = await makeFetch(`${base}/api/auth/me`, { headers: { cookie } });
    const b4 = await r4.json().catch(() => ({}));
    record('GET /api/auth/me', r4.ok && b4.user && b4.user.name, { status: r4.status, body: b4 });

    // /api/matatus (may fail if DB not initialized)
    let ok5 = false; let info5;
    try {
      const r5 = await makeFetch(`${base}/api/matatus`, { headers: { cookie } });
      const b5 = await r5.json().catch(() => ({}));
      ok5 = r5.ok && Array.isArray(b5.items);
      info5 = { status: r5.status, body: b5 };
    } catch (e) {
      info5 = { error: String(e) };
    }
    record('GET /api/matatus', ok5, info5);
  } catch (e) {
    console.error('Smoke test error:', e);
  } finally {
    server.close();
  }

  const summary = {
    pass: results.filter(r => r.ok).length,
    total: results.length,
    results
  };
  console.log(JSON.stringify(summary, null, 2));
}

run();
