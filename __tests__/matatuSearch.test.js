const request = require('supertest');

function loadServer() {
  delete require.cache[require.resolve('../server')];
  return require('../server');
}

function createSearchSupabaseMock(exact, fuzzy) {
  return {
    from: jest.fn().mockImplementation(() => {
      return {
        select: jest.fn().mockReturnThis(),
        filter: jest.fn().mockReturnThis(),
        ilike: jest.fn().mockReturnThis(),
        order: jest.fn().mockReturnThis(),
        eq: jest.fn().mockReturnThis(),
        limit: jest.fn().mockResolvedValue(fuzzy || { data: [], error: null }),
        maybeSingle: jest.fn().mockResolvedValue(exact || { data: null, error: null })
      };
    })
  };
}

async function login(app) {
  const res = await request(app)
    .post('/api/auth/login')
    .send({ username: process.env.ADMIN_USER, password: process.env.ADMIN_PASSWORD });
  expect(res.status).toBe(200);
  const cookie = res.headers['set-cookie']?.[0];
  expect(cookie).toBeTruthy();
  return cookie;
}

describe('GET /api/matatus/search', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  test('returns empty list when no plate provided', async () => {
    const app = loadServer();
    app.locals.supabase = createSearchSupabaseMock({ data: null, error: null }, { data: [], error: null });
    const cookie = await login(app);

    const res = await request(app).get('/api/matatus/search').set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('items');
    expect(Array.isArray(res.body.items)).toBe(true);
    expect(res.body.items.length).toBe(0);
  });

  test('returns exact plate match when available', async () => {
    const exact = {
      data: {
        matatu_id: 'mat-1',
        plate: 'KDA 123A',
        till_number: '123456',
        ussd_code: '1234',
        total_success: 3,
        last_tx_at: '2025-01-01T12:00:00Z'
      },
      error: null
    };
    const app = loadServer();
    app.locals.supabase = createSearchSupabaseMock({ data: exact.data, error: null }, { data: [], error: null });
    const cookie = await login(app);

    const res = await request(app).get('/api/matatus/search?plate=KDA123A').set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.body.items[0]).toMatchObject({ plate: 'KDA 123A', matatu_id: 'mat-1' });
    expect(res.body.meta).toMatchObject({ total: 1, query: 'KDA123A' });
  });

  test('falls back to fuzzy search results when exact is missing', async () => {
    const fuzzy = {
      data: [
        { matatu_id: 'mat-2', plate: 'KDA 321B', till_number: '999999', ussd_code: null },
        { matatu_id: 'mat-3', plate: 'KDA 777C', till_number: null, ussd_code: '4321' }
      ],
      error: null
    };
    const app = loadServer();
    app.locals.supabase = createSearchSupabaseMock({ data: null, error: null }, fuzzy);
    const cookie = await login(app);

    const res = await request(app).get('/api/matatus/search?plate=KDA').set('Cookie', cookie);

    expect(res.status).toBe(200);
    expect(res.body.items.length).toBe(2);
    expect(res.body.items[0].plate).toBe('KDA 321B');
    expect(res.body.items[1].plate).toBe('KDA 777C');
  });
});
