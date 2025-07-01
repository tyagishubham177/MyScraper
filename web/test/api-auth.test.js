import test from 'node:test';
import assert from 'assert';

function makeRes() {
  return {
    code: null,
    data: null,
    status(c) { this.code = c; return this; },
    json(d) { this.data = d; },
  };
}

test('missing secret returns 500', async () => {
  const req = { headers: {} };
  const res = makeRes();
  process.env.JWT_SECRET = '';
  const { requireAdmin } = await import('../utils/auth.js?' + Date.now());
  assert.equal(requireAdmin(req, res), null);
  assert.equal(res.code, 500);
  assert.deepEqual(res.data, { message: 'Server configuration missing' });
});

test('missing auth header returns 401', async () => {
  const req = { headers: {} };
  const res = makeRes();
  process.env.JWT_SECRET = 's';
  const { requireAdmin } = await import('../utils/auth.js?' + Date.now());
  assert.equal(requireAdmin(req, res), null);
  assert.equal(res.code, 401);
});

test('invalid token returns 401', async () => {
  const jwt = await import('jsonwebtoken');
  jwt.default.verify = () => { throw new Error('bad'); };
  const req = { headers: { Authorization: 'Bearer xx' } };
  const res = makeRes();
  process.env.JWT_SECRET = 's';
  const { requireAdmin } = await import('../utils/auth.js?' + Date.now());
  assert.equal(requireAdmin(req, res), null);
  assert.equal(res.code, 401);
});

test('non admin role returns 403', async () => {
  const jwt = await import('jsonwebtoken');
  jwt.default.verify = () => ({ role: 'user' });
  const req = { headers: { Authorization: 'Bearer xx' } };
  const res = makeRes();
  process.env.JWT_SECRET = 's';
  const { requireAdmin } = await import('../utils/auth.js?' + Date.now());
  assert.equal(requireAdmin(req, res), null);
  assert.equal(res.code, 403);
});

test('valid admin returns decoded object', async () => {
  const decoded = { role: 'admin' };
  const jwt = await import('jsonwebtoken');
  jwt.default.verify = () => decoded;
  const req = { headers: { Authorization: 'Bearer good' } };
  const res = makeRes();
  process.env.JWT_SECRET = 's';
  const { requireAdmin } = await import('../utils/auth.js?' + Date.now());
  const result = requireAdmin(req, res);
  assert.deepEqual(result, decoded);
  assert.equal(res.code, null);
});
