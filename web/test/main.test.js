import test from 'node:test';
import assert from 'assert';

function makeEl() {
  return {
    children: [],
    appendChild(child){ this.children.push(child); },
    addEventListener(){},
    querySelector(){ return null; },
    querySelectorAll(){ return []; },
    style:{},
    classList:{ add(){}, remove(){} }
  };
}

test('registers DOMContentLoaded handler', async () => {
  const events = {};
  global.document = {
    addEventListener: (ev, cb) => events[ev] = cb,
    getElementById: () => makeEl(),
    createElement: () => makeEl(),
    body: makeEl(),
    querySelector: () => makeEl(),
    querySelectorAll: () => []
  };
  global.window = {};
  await import('../components/main/main.js?' + Date.now());
  assert(events['DOMContentLoaded']);
});


function makeLoginEl(){
  return {
    style:{},
    classList:{ add(){}, remove(){} },
    addEventListener(){},
    prepend(){},
    appendChild(){},
    querySelector(){ return null; },
    querySelectorAll(){ return []; },
    disabled:false,
    value:''
  };
}

function setupLoginEnv(){
  const elements = {
    'login-popup': makeLoginEl(),
    'admin-role-btn': makeLoginEl(),
    'user-role-btn': makeLoginEl(),
    'admin-section': makeLoginEl(),
    'user-section': makeLoginEl(),
    'admin-email': makeLoginEl(),
    'admin-password': makeLoginEl(),
    'admin-login-btn': makeLoginEl(),
    'admin-error-message': makeLoginEl(),
    'user-email': makeLoginEl(),
    'user-email-wrapper': makeLoginEl(),
    'user-login-btn': makeLoginEl(),
    'user-error-message': makeLoginEl(),
    'user-contact-links': makeLoginEl(),
    'user-mail-btn': makeLoginEl(),
    'user-reddit-link': makeLoginEl(),
    'main-app-content': makeLoginEl(),
    'global-loader': makeLoginEl()
  };
  const events = {};
  global.document = {
    addEventListener: (ev, cb) => events[ev] = cb,
    getElementById: id => elements[id] || makeLoginEl(),
    createElement: () => makeLoginEl(),
    body: { prepend(){}, style:{} },
    querySelector: () => makeLoginEl(),
    querySelectorAll: () => []
  };
  global.window = { location:{ href:'' }, lucide:{ createIcons(){} } };
  global.localStorage = { getItem: () => null, setItem(){}, removeItem(){} };
  global.fetch = async () => ({ text: async () => '' });
  return { elements, events };
}

test('DOMContentLoaded triggers login popup', async () => {
  const { elements, events } = setupLoginEnv();
  await import('../components/main/main.js?' + Date.now());
  events['DOMContentLoaded']();
  assert.equal(elements['login-popup'].style.display, 'flex');
});
