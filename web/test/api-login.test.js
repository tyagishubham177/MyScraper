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

async function load(compareResult = true, attemptData, options = {}) {
  const bcrypt = await import('bcryptjs');
  bcrypt.default.compare = async () => compareResult;
  const jwt = await import('jsonwebtoken');
  jwt.default.sign = () => 'tok';
  const mod = await import('../api/login.js?' + Date.now());
  const data = attemptData || { count: 0, delay: 0, lockUntil: 0 };
  const attemptKey = options.attemptKey || 'admin_login_attempts';
  const store = new Map();
  store.set(attemptKey, data);
  if (options.recipients) {
    store.set('recipients', options.recipients);
  }

  const kvMock = {
    get: async key => store.get(key),
    set: async (key, value) => {
      store.set(key, value);
      if (key === attemptKey) {
        Object.assign(data, value);
      }
    },
    del: async key => {
      store.delete(key);
      if (key === attemptKey) {
        data.count = 0;
        data.delay = 0;
        data.lockUntil = 0;
        store.set(key, data);
      }
    }
  };

  if (options.kvOverrides) {
    Object.assign(kvMock, options.kvOverrides);
  }

  mod.__setKv(kvMock);
  return { handler: mod.default, data, store };
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

test('admin login ignores email casing', async () => {
  const { handler } = await load(true);
  process.env.ADMIN_EMAIL = 'Admin@Example.com';
  process.env.ADMIN_PASSWORD_HASH = 'h';
  process.env.JWT_SECRET = 's';
  const res = makeRes();
  await handler({ method: 'POST', body:{ email:'admin@example.COM', password:'p' } }, res);
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

test('user login matches email case-insensitively', async () => {
  const attemptKey = 'user_login_attempt_user@example.com';
  const { handler } = await load(true, undefined, {
    attemptKey,
    recipients: [{ email: 'User@Example.com' }]
  });
  const res = makeRes();
  await handler({ method: 'POST', body:{ email:'USER@example.COM' } }, res);
  assert.equal(res.code, 200);
  assert.deepEqual(res.data, { message: 'ok' });
});

test('user login succeeds when recipients stored in hash', async () => {
  const { handler } = await load(true, undefined, {
    attemptKey: 'user_login_attempt_hash@example.com',
    kvOverrides: {
      async hgetall(key) {
        if (key === 'recipients:data') {
          return {
            r1: JSON.stringify({ email: 'hash@example.com', pincode: '110001' })
          };
        }
        return null;
      }
    }
  });
  const res = makeRes();
  await handler({ method: 'POST', body:{ email:'hash@example.com' } }, res);
  assert.equal(res.code, 200);
  assert.deepEqual(res.data, { message: 'ok' });
});
