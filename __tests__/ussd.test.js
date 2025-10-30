const request = require('supertest');

function loadServer() {
  delete require.cache[require.resolve('../server')];
  return require('../server');
}

function createSupabaseMock(responses) {
  const queue = Array.isArray(responses) ? [...responses] : [responses];
  const builder = {
    select: jest.fn().mockReturnThis(),
    filter: jest.fn().mockReturnThis(),
    ilike: jest.fn().mockReturnThis(),
    order: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    maybeSingle: jest.fn().mockImplementation(() => Promise.resolve(queue.shift() || { data: null, error: null }))
  };
  return {
    from: jest.fn().mockReturnValue(builder),
    __builder: builder
  };
}

describe('/ussd handler', () => {
  beforeEach(() => {
    process.env.USSD_GATEWAY_SECRET = '';
  });

  test('returns root menu when no input provided', async () => {
    const app = loadServer();
    const res = await request(app)
      .post('/ussd')
      .send({ sessionId: 'abc', phoneNumber: '254712345678', text: '' });

    expect(res.status).toBe(200);
    expect(res.type).toBe('text/plain');
    expect(res.text).toMatch(/^CON /);
    expect(res.text).toContain('Karibu TekeTeke');
  });

  test('prompts for plate when option 1 selected', async () => {
    const app = loadServer();
    const res = await request(app)
      .post('/ussd')
      .send({ sessionId: 'abc', phoneNumber: '254712345678', text: '1' });

    expect(res.status).toBe(200);
    expect(res.text).toMatch(/^CON /);
    expect(res.text).toContain('Ingiza nambari ya plate');
  });

  test('returns matatu summary when plate is found', async () => {
    const responses = [
      { data: null, error: null },
      {
        data: {
          plate: 'KDA 123A',
          till_number: '123456',
          ussd_code: '1234',
          total_success: 12,
          last_tx_at: '2025-01-01T12:34:56Z'
        },
        error: null
      }
    ];
    const supabaseMock = createSupabaseMock(responses);
    const app = loadServer();
    app.locals.supabase = supabaseMock;

    const res = await request(app)
      .post('/ussd')
      .send({ sessionId: 'sess-1', phoneNumber: '254712345678', text: '1*KDA123A' });

    expect(res.status).toBe(200);
    expect(res.text).toMatch(/^END /);
    expect(res.text).toContain('KDA 123A');
    expect(res.text).toContain('*123*1234#');
    expect(res.text).toContain('Mafanikio: 12');
  });

  test('gracefully handles unknown plates', async () => {
    const responses = [
      { data: null, error: null },
      { data: null, error: null }
    ];
    const supabaseMock = createSupabaseMock(responses);
    const app = loadServer();
    app.locals.supabase = supabaseMock;

    const res = await request(app)
      .post('/ussd')
      .send({ sessionId: 'sess-2', phoneNumber: '254712345678', text: '1*UNKNOWN' });

    expect(res.status).toBe(200);
    expect(res.text).toMatch(/^END /);
    expect(res.text).toContain('Hatukupata matatu hiyo');
  });
});
