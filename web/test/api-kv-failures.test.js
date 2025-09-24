import test from 'node:test';
import assert from 'assert';

function makeRes() {
  return {
    code: null,
    data: null,
    headers: {},
    status(c) { this.code = c; return this; },
    json(d) { this.data = d; return this; },
    setHeader(k, v) { this.headers[k] = v; return this; }
  };
}

test('POST /api/products returns 500 when kv.get fails and avoids kv.set', async () => {
  const modulePath = '../api/products.js?' + Date.now();
  const mod = await import(modulePath);
  let setCalled = false;
  mod.__setKv({
    async get() { throw new Error('kv down'); },
    async set() { setCalled = true; }
  });
  mod.__setRequireAdmin(() => true);

  const req = {
    method: 'POST',
    body: { url: 'https://example.com', name: 'Example' },
    headers: {}
  };
  const res = makeRes();
  await mod.default(req, res);
  assert.equal(res.code, 500);
  assert.equal(res.data?.message, 'Error saving product to KV');
  assert.equal(setCalled, false);
  mod.__resetKv();
  mod.__resetRequireAdmin();
});

test('POST /api/recipients surfaces kv errors without writing empty data', async () => {
  const modulePath = '../api/recipients.js?' + Date.now();
  const mod = await import(modulePath);
  let setCalled = false;
  mod.__setKv({
    async get() { throw new Error('kv down'); },
    async set() { setCalled = true; }
  });
  mod.__setRequireAdmin(() => true);

  const req = {
    method: 'POST',
    body: { email: 'user@example.com', pincode: '201305' },
    headers: {}
  };
  const res = makeRes();
  await mod.default(req, res);
  assert.equal(res.code, 500);
  assert.equal(res.data?.message, 'Error saving recipient to KV');
  assert.equal(setCalled, false);
  mod.__resetKv();
  mod.__resetRequireAdmin();
});

test('POST /api/subscriptions reports kv failure without persisting data', async () => {
  const modulePath = '../api/subscriptions.js?' + Date.now();
  const mod = await import(modulePath);
  let setCalled = false;
  mod.__setKv({
    async get(key) {
      if (key === 'recipients') {
        return [{ id: 'r1', email: 'user@example.com' }];
      }
      if (key === 'products') {
        return [{ id: 'p1', name: 'Example' }];
      }
      if (key === 'subscriptions') {
        throw new Error('kv down');
      }
      throw new Error('unexpected key ' + key);
    },
    async set() { setCalled = true; }
  });

  const req = {
    method: 'POST',
    body: { recipient_id: 'r1', product_id: 'p1', start_time: '08:00', end_time: '20:00', paused: false }
  };
  const res = makeRes();
  await mod.default(req, res);
  assert.equal(res.code, 500);
  assert.equal(res.data?.message, 'Error creating subscription in KV');
  assert.equal(setCalled, false);
  mod.__resetKv();
});
