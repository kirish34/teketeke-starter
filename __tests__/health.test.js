const request = require('supertest');

function loadServer() {
  delete require.cache[require.resolve('../server')];
  return require('../server');
}

describe('health endpoint', () => {
  test('returns ok status and skips supabase when configured', async () => {
    process.env.HEALTHCHECK_SKIP_DB = 'true';
    const app = loadServer();
    const res = await request(app).get('/healthz');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('status', 'ok');
    expect(res.body.checks).toHaveProperty('supabase');
    expect(res.body.checks.supabase).toHaveProperty('status', 'skipped');
    expect(typeof res.body.uptime).toBe('number');
  });
});
