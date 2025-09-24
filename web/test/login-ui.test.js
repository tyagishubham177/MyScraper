import test from 'node:test';
import assert from 'assert';

function makeEl() {
  return {
    style: {},
    classList: { add(){ this.added=true; }, remove(){ this.removed=true; } },
    events: {},
    addEventListener(ev, cb){ this.events[ev] = cb; },
    prepend(){},
    appendChild(){},
    querySelector(){ return null; },
    querySelectorAll(){ return []; },
    disabled: false,
    value: ''
  };
}

function setupEnv(storage={}) {
  const elements = {
    'login-popup': makeEl(),
    'admin-role-btn': makeEl(),
    'user-role-btn': makeEl(),
    'admin-section': makeEl(),
    'user-section': makeEl(),
    'admin-email': makeEl(),
    'admin-password': makeEl(),
    'admin-login-btn': makeEl(),
    'admin-error-message': makeEl(),
    'user-email': makeEl(),
    'user-email-wrapper': makeEl(),
    'user-login-btn': makeEl(),
    'user-error-message': makeEl(),
    'user-contact-links': makeEl(),
    'user-mail-btn': makeEl(),
    'user-reddit-link': makeEl(),
    'main-app-content': makeEl(),
    'global-loader': makeEl()
  };
  const events = {};
  global.document = {
    addEventListener: (ev, cb) => { events[ev] = cb; },
    getElementById: id => elements[id] || null,
    createElement: () => makeEl(),
    body: { prepend(){}, style:{} }
  };
  global.window = { location: { href: '' }, lucide: { createIcons(){} } };
  global.localStorage = {
    getItem: key => storage[key] || null,
    setItem: (k,v) => { storage[k] = v; },
    removeItem: k => { delete storage[k]; }
  };
  global.fetch = async () => ({ text: async () => '' });
  return { elements, events, storage };
}

async function loadModule() {
  return await import('../components/login/login.js?' + Date.now());
}

test('redirects to admin when token stored', async () => {
  const env = setupEnv({ authToken: 'tok' });
  const mod = await loadModule();
  await mod.initLogin();
  assert.equal(global.window.location.href, 'components/admin-main/admin.html');
});

test('redirects to user page when user email stored', async () => {
  const env = setupEnv({ userEmail: 'x@example.com' });
  const mod = await loadModule();
  await mod.initLogin();
  assert.equal(global.window.location.href, 'components/user-main/user.html');
});

test('shows login popup when no credentials', async () => {
  const env = setupEnv();
  const mod = await loadModule();
  await mod.initLogin();
  assert.equal(env.elements['login-popup'].style.display, 'flex');
});

test('fetches login html when popup missing', async () => {
  const env = setupEnv();
  env.elements['login-popup'] = null;
  let fetched = false;
  global.fetch = async (url) => {
    if (url.includes('login.html')) {
      fetched = true;
      return { text: async () => '<div id="login-popup"></div>' };
    }
    return { json: async () => ({}) , ok: true };
  };
  global.document.createElement = () => ({ firstElementChild: { id: 'login-popup', style: {}, classList:{ add(){}, remove(){} } } });
  global.document.body.prepend = el => { env.elements['login-popup'] = el; };
  const mod = await loadModule();
  await mod.initLogin();
  assert.ok(fetched);
  assert.ok(env.elements['login-popup']);
});

test('admin role button shows admin section', async () => {
  const env = setupEnv();
  const mod = await loadModule();
  await mod.initLogin();
  env.elements['admin-role-btn'].events.click();
  assert.equal(env.elements['admin-section'].style.display, 'block');
  assert.equal(env.elements['user-section'].style.display, 'none');
});

test('user role button shows user section', async () => {
  const env = setupEnv();
  const mod = await loadModule();
  await mod.initLogin();
  env.elements['user-role-btn'].events.click();
  assert.equal(env.elements['user-section'].style.display, 'block');
  assert.equal(env.elements['admin-section'].style.display, 'none');
});

test('admin login with empty fields shows error', async () => {
  const env = setupEnv();
  const mod = await loadModule();
  await mod.initLogin();
  env.elements['admin-email'].value = '';
  env.elements['admin-password'].value = '';
  await env.elements['admin-login-btn'].events.click();
  assert.equal(env.elements['admin-error-message'].textContent, 'Please enter both email and password.');
  assert.equal(env.elements['admin-error-message'].style.display, 'block');
});

test('admin login shows countdown on lockout', async () => {
  const env = setupEnv();
  global.fetch = async (url) => ({ ok: false, json: async () => ({ wait: 1 }) });
  global.setInterval = (fn) => { fn(); return 1; };
  const mod = await loadModule();
  await mod.initLogin();
  env.elements['admin-email'].value = 'a@a';
  env.elements['admin-password'].value = 'p';
  await env.elements['admin-login-btn'].events.click();
  assert.ok(env.storage['adminLockUntil']);
  assert.ok(env.elements['admin-login-btn'].disabled);
});

test('admin login stores normalized and display email', async () => {
  const env = setupEnv();
  global.fetch = async (_url, opts) => ({ ok: true, json: async () => ({ token: 't' }) });
  const mod = await loadModule();
  await mod.initLogin();
  env.elements['admin-email'].value = 'Admin@Example.com ';
  env.elements['admin-password'].value = 'secret';
  await env.elements['admin-login-btn'].events.click();
  assert.equal(env.storage.adminEmail, 'admin@example.com');
  assert.equal(env.storage.adminEmailDisplay, 'Admin@Example.com');
});

test('user login blank email shows error', async () => {
  const env = setupEnv();
  const mod = await loadModule();
  await mod.initLogin();
  env.elements['user-email'].value = '';
  await env.elements['user-login-btn'].events.click();
  assert.equal(env.elements['user-error-message'].textContent, 'Please enter your email.');
  assert.equal(env.elements['user-error-message'].style.display, 'block');
});

test('user login success redirects', async () => {
  const env = setupEnv();
  global.fetch = async () => ({ ok: true, json: async () => ({ token: 't' }) });
  const mod = await loadModule();
  await mod.initLogin();
  env.elements['user-email'].value = 'u@e';
  await env.elements['user-login-btn'].events.click();
  assert.equal(global.window.location.href, 'components/user-main/user.html');
});

test('user login stores normalized and display email', async () => {
  const env = setupEnv();
  let body;
  global.fetch = async (_url, opts) => {
    body = opts ? JSON.parse(opts.body) : null;
    return { ok: true, json: async () => ({ token: 't' }) };
  };
  const mod = await loadModule();
  await mod.initLogin();
  env.elements['user-email'].value = 'User@Example.COM ';
  await env.elements['user-login-btn'].events.click();
  assert.equal(env.storage.userEmail, 'user@example.com');
  assert.equal(env.storage.userEmailDisplay, 'User@Example.COM');
  assert.equal(body.email, 'user@example.com');
});

test('user mail button opens gmail on desktop', async () => {
  const env = setupEnv();
  const mod = await loadModule();
  await mod.initLogin();
  let opened = '';
  global.window.open = (url) => { opened = url; };
  global.window.navigator = { userAgent: 'desktop' };
  global.navigator = global.window.navigator;
  env.elements['user-email'].value = 'me@example.com';
  env.elements['user-mail-btn'].events.click({ preventDefault(){} });
  const mailUrl = new URL(opened);
  assert.equal(mailUrl.hostname, 'mail.google.com');
});

test('user reddit link opens compose url', async () => {
  const env = setupEnv();
  const mod = await loadModule();
  await mod.initLogin();
  let opened = '';
  global.window.open = (url) => { opened = url; };
  env.elements['user-email'].value = 'me@example.com';
  env.elements['user-reddit-link'].events.click({ preventDefault(){} });
  const redditUrl = new URL(opened);
  assert.equal(redditUrl.hostname, 'www.reddit.com');
  assert.ok(redditUrl.pathname.startsWith('/message/compose'));
});
