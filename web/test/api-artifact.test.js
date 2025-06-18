import test from 'node:test';
import assert from 'assert';

function makeRes() {
  return {
    code: null,
    sent: null,
    headers: {},
    status(c){ this.code = c; return this; },
    send(d){ this.sent = d; },
    setHeader(k,v){ this.headers[k] = v; }
  };
}


async function load(adminReturn) {
  const mod = await import('../api/artifact.js?' + Date.now());
  mod.__setRequireAdmin(() => adminReturn);
  return mod;
}

test('rejects non-GET', async () => {
  const res = makeRes();
  const { default: handler } = await import('../api/artifact.js?' + Date.now());
  await handler({ method: 'POST' }, res);
  assert.equal(res.code, 405);
  assert.equal(res.sent, 'Method Not Allowed');
});

test('requires admin', async () => {
  const { default: handler } = await load(null);
  const res = makeRes();
  await handler({ method: 'GET', query:{} }, res);
  assert.equal(res.code, null);
  assert.equal(res.sent, null);
});

test('missing id', async () => {
  const { default: handler } = await load(true);
  const res = makeRes();
  await handler({ method: 'GET', query:{} }, res);
  assert.equal(res.code, 400);
  assert.equal(res.sent, 'Missing id');
});

test('fetch error propagates', async () => {
  const { default: handler } = await load(true);
  global.fetch = async () => ({ ok: false, status: 404, text: async () => 'oops' });
  process.env.GH_REPO = 'r';
  process.env.GH_TOKEN = 't';
  const res = makeRes();
  await handler({ method: 'GET', query:{ id: '1' } }, res);
  assert.equal(res.code, 404);
  assert.equal(res.sent, 'oops');
});

test('successful fetch sends zip', async () => {
  const { default: handler } = await load(true);
  const buf = Buffer.from('zip');
  global.fetch = async () => ({ ok: true, arrayBuffer: async () => buf });
  process.env.GH_REPO = 'r';
  process.env.GH_TOKEN = 't';
  const res = makeRes();
  await handler({ method: 'GET', query:{ id:'1' } }, res);
  assert.equal(res.headers['Content-Type'], 'application/zip');
  assert.deepStrictEqual(res.sent, buf);
});
