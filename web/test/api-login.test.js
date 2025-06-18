import test from 'node:test';
import assert from 'assert';

function makeRes() {
  return {
    code: null,
    data: null,
    status(c){ this.code = c; return this; },
    json(d){ this.data = d; return this; },
    end(d){ this.data = d; return this; },
    setHeader(){ }
  };
}

async function load(compareResult = true, attemptData) {
  const bcrypt = await import('bcryptjs');
  bcrypt.default.compare = async () => compareResult;
  const jwt = await import('jsonwebtoken');
  jwt.default.sign = () => 'tok';
  const mod = await import('../api/login.js?' + Date.now());
  const data = attemptData || { count: 0, delay: 0, lockUntil: 0 };
  mod.__setKv({
    get: async () => data,
    set: async (_k, v) => Object.assign(data, v),
    del: async () => { data.count = 0; data.delay = 0; data.lockUntil = 0; }
  });
  return { handler: mod.default, data };
}

test('rejects non POST', async () => {
  const { handler } = await load();
  const res = makeRes();
  await handler({ method: 'GET' }, res);
  assert.equal(res.code, 405);
});

test('missing credentials', async () => {
  const { handler } = await load();
  const res = makeRes();
  await handler({ method: 'POST', body:{} }, res);
  assert.equal(res.code, 400);
});

test('invalid email', async () => {
  const { handler } = await load(false);
  process.env.ADMIN_EMAIL = 'a@a';
  process.env.ADMIN_PASSWORD_HASH = 'h';
  process.env.JWT_SECRET = 's';
  const res = makeRes();
  await handler({ method: 'POST', body:{ email:'wrong', password:'p' } }, res);
  assert.equal(res.code, 401);
});

test('successful login', async () => {
  const { handler } = await load(true);
  process.env.ADMIN_EMAIL = 'a@a';
  process.env.ADMIN_PASSWORD_HASH = 'h';
  process.env.JWT_SECRET = 's';
  const res = makeRes();
  await handler({ method: 'POST', body:{ email:'a@a', password:'p' } }, res);
  assert.equal(res.code, 200);
  assert.deepEqual(res.data, { token: 'tok' });
});

test('missing server config returns 500', async () => {
  const { handler } = await load(true);
  process.env.ADMIN_EMAIL = '';
  process.env.ADMIN_PASSWORD_HASH = '';
  process.env.JWT_SECRET = '';
  const res = makeRes();
  await handler({ method: 'POST', body:{ email:'a@a', password:'p' } }, res);
  assert.equal(res.code, 500);
});

test('invalid password triggers lockout', async () => {
  const attempt = { count: 2, delay: 0, lockUntil: 0 };
  const { handler, data } = await load(false, attempt);
  process.env.ADMIN_EMAIL = 'a@a';
  process.env.ADMIN_PASSWORD_HASH = 'h';
  process.env.JWT_SECRET = 's';
  const res = makeRes();
  await handler({ method: 'POST', body:{ email:'a@a', password:'bad' } }, res);
  assert.equal(res.code, 429);
  assert.equal(data.count, 3);
  assert.ok(data.delay >= 60);
  assert.ok(data.lockUntil > Date.now());
});

test('locked account returns wait time', async () => {
  const attempt = { count: 3, delay: 120, lockUntil: Date.now() + 60000 };
  const { handler } = await load(false, attempt);
  process.env.ADMIN_EMAIL = 'a@a';
  process.env.ADMIN_PASSWORD_HASH = 'h';
  process.env.JWT_SECRET = 's';
  const res = makeRes();
  await handler({ method: 'POST', body:{ email:'a@a', password:'bad' } }, res);
  assert.equal(res.code, 429);
  assert.ok(res.data.wait > 0);
});
