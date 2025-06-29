import test from 'node:test';
import assert from 'assert';

// capture event handler

test('registers DOMContentLoaded handler', async () => {
  const events = {};
  function makeEl() {
    return { style: {}, classList: { add(){}, remove(){} } };
  }
  global.document = {
    addEventListener: (ev, cb) => events[ev] = cb,
    getElementById: () => makeEl(),
    createElement: () => makeEl()
  };
  await import('../components/login/login-main.js?' + Date.now());
  assert(events['DOMContentLoaded']);
});

function makeEl() {
  return {
    style: {},
    classList: { add(){}, remove(){} },
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
    'global-loader': makeEl(),
    'particles-js-bg': makeEl()
  };
  const events = {};
  global.document = {
    addEventListener: (ev, cb) => { events[ev] = cb; },
    getElementById: id => elements[id] || null,
    createElement: () => makeEl(),
    body: { prepend(){}, style:{} },
    querySelector: () => null,
    querySelectorAll: () => []
  };
  global.window = { location: { href: '' }, lucide: { createIcons(){} }, addEventListener(){}, innerHeight: 0 };
  global.localStorage = {
    getItem: key => storage[key] || null,
    setItem: (k,v) => { storage[k] = v; },
    removeItem: k => { delete storage[k]; }
  };
  global.fetch = async () => ({ text: async () => '' });
  global.particlesJS = () => {};
  global.bootstrap = { Tooltip: function() {} };
  return { elements, events };
}

test('DOMContentLoaded triggers login flow', async () => {
  const { elements, events } = setupEnv();
  await import('../components/login/login-main.js?' + Date.now());
  events['DOMContentLoaded']();
  assert.equal(elements['login-popup'].style.display, 'flex');
});

