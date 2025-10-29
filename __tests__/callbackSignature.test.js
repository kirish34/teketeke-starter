function loadServer() {
  delete require.cache[require.resolve('../server')];
  return require('../server');
}

describe('verifyCallbackSignature', () => {
  test('accepts a valid signature and rejects tampered payload', () => {
    process.env.CALLBACK_SECRET = 'unit-test-secret';
    const server = loadServer();
    const { verifyCallbackSignature } = server;

    const payload = JSON.stringify({ hello: 'world' });
    const sig = require('crypto').createHmac('sha256', process.env.CALLBACK_SECRET).update(payload).digest('hex');
    const reqOk = { rawBody: payload, headers: { 'x-callback-signature': sig } };
    expect(verifyCallbackSignature(reqOk)).toBe(true);

    const reqBad = { rawBody: payload, headers: { 'x-callback-signature': sig.slice(2) + 'ab' } };
    expect(verifyCallbackSignature(reqBad)).toBe(false);
  });
});
