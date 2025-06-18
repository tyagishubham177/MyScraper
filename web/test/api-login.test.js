import test from 'node:test';
import assert from 'assert';

function makeRes() {
  return {
    code: null,
    data: null,
    status(c){ this.code = c; return this; },
    json(d){ this.data = d; },
    setHeader(){ }
  };
}

async function mockDeps(t, compareResult=true) {
  await t.mock.module('bcryptjs', { default: { compare: async () => compareResult } });
  await t.mock.module('jsonwebtoken', { default: { sign: () => 'tok' } });
  await t.mock.module('@vercel/kv', { kv: { get: async () => null, set: async () => {}, del: async () => {} } });
}

test('rejects non POST', async t => {
  await mockDeps(t);
  const res = makeRes();
  const { default: handler } = await import('../api/login.js?' + Date.now());
  await handler({ method: 'GET' }, res);
  assert.equal(res.code, 405);
});

test('missing credentials', async t => {
  await mockDeps(t);
  const res = makeRes();
  const { default: handler } = await import('../api/login.js?' + Date.now());
  await handler({ method: 'POST', body:{} }, res);
  assert.equal(res.code, 400);
});

test('invalid email', async t => {
  await mockDeps(t, false);
  process.env.ADMIN_EMAIL = 'a@a';
  process.env.ADMIN_PASSWORD_HASH = 'h';
  process.env.JWT_SECRET = 's';
  const res = makeRes();
  const { default: handler } = await import('../api/login.js?' + Date.now());
  await handler({ method: 'POST', body:{ email:'wrong', password:'p' } }, res);
  assert.equal(res.code, 401);
});

test('successful login', async t => {
  await mockDeps(t, true);
  process.env.ADMIN_EMAIL = 'a@a';
  process.env.ADMIN_PASSWORD_HASH = 'h';
  process.env.JWT_SECRET = 's';
  const res = makeRes();
  const { default: handler } = await import('../api/login.js?' + Date.now());
  await handler({ method: 'POST', body:{ email:'a@a', password:'p' } }, res);
  assert.equal(res.code, 200);
  assert.deepEqual(res.data, { token: 'tok' });
});
