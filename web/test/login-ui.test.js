import test from 'node:test';
import assert from 'assert';

function makeEl() {
  return {
    style: {},
    classList: { add(){ this.added=true; }, remove(){ this.removed=true; } },
    addEventListener(){},
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
