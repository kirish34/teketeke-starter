function loadServer() {
  delete require.cache[require.resolve('../server')];
  return require('../server');
}

describe('createRateLimiter', () => {
  test('enforces limits after the configured threshold', () => {
    const server = loadServer();
    const limiter = server.createRateLimiter({
      windowMs: 1000,
      max: 2,
      keyGenerator: () => 'tester',
      name: 'testLimiter'
    });

    const req = { ip: '127.0.0.1', originalUrl: '/test', requestId: 'test-req' };
    const next = jest.fn();
    const res = {
      statusCode: 200,
      headers: {},
      set(key, value) {
        this.headers[key] = value;
      },
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(body) {
        this.body = body;
        return this;
      }
    };

    limiter(req, res, next);
    limiter(req, res, next);
    expect(next).toHaveBeenCalledTimes(2);

    limiter(req, res, next);
    expect(res.statusCode).toBe(429);
    expect(res.body).toEqual({ error: 'rate_limited', request_id: 'test-req' });
  });
});
