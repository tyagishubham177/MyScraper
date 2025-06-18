import test from 'node:test';
import assert from 'assert';

function makeRes() {
  return {
    code: null,
    data: null,
    status(c){ this.code = c; return this; },
    json(d){ this.data = d; },
    end(d){ this.data = d; },
    setHeader(){ }
  };
}

async function load(compareResult=true) {
  const bcrypt = await import('bcryptjs');
  bcrypt.default.compare = async () => compareResult;
  const jwt = await import('jsonwebtoken');
  jwt.default.sign = () => 'tok';
  const mod = await import('../api/login.js?' + Date.now());
  mod.__setKv({ get: async () => null, set: async () => {}, del: async () => {} });
  return mod.default;
}

test('rejects non POST', async () => {
  const handler = await load();
  const res = makeRes();
  await handler({ method: 'GET' }, res);
  assert.equal(res.code, 405);
});

test('missing credentials', async () => {
  const handler = await load();
  const res = makeRes();
  await handler({ method: 'POST', body:{} }, res);
  assert.equal(res.code, 400);
});

test('invalid email', async () => {
  const handler = await load(false);
  process.env.ADMIN_EMAIL = 'a@a';
  process.env.ADMIN_PASSWORD_HASH = 'h';
  process.env.JWT_SECRET = 's';
  const res = makeRes();
  await handler({ method: 'POST', body:{ email:'wrong', password:'p' } }, res);
  assert.equal(res.code, 401);
});

test('successful login', async () => {
  const handler = await load(true);
  process.env.ADMIN_EMAIL = 'a@a';
  process.env.ADMIN_PASSWORD_HASH = 'h';
  process.env.JWT_SECRET = 's';
  const res = makeRes();
  await handler({ method: 'POST', body:{ email:'a@a', password:'p' } }, res);
  assert.equal(res.code, 200);
  assert.deepEqual(res.data, { token: 'tok' });
});
