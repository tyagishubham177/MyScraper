import test from 'node:test';
import assert from 'assert';

function makeEl() {
  return {
    addEventListener(){},
    appendChild(){},
    prepend(){},
    querySelector(){ return null; },
    querySelectorAll(){ return []; },
    style: {},
    classList: { add(){}, remove(){} }
  };
}

test('handler redirects to index when no token', async () => {
  const events = {};
  const elements = { loader: makeEl(), status: makeEl(), 'html-editor': makeEl(), 'html-preview': makeEl() };
  global.document = {
    addEventListener: (ev, cb) => events[ev] = cb,
    getElementById: id => elements[id] || makeEl(),
    createElement: () => makeEl(),
    querySelectorAll: () => [],
    querySelector: () => null,
    body: Object.assign(makeEl(), { scrollHeight: 0 })
  };
  global.window = { location: { href: '' }, addEventListener(){}, innerHeight:0 };
  global.localStorage = { getItem: () => null };
  global.bootstrap = { Modal: function(){ return { show(){} }; }, Tooltip: function(){} };
  global.window.fetchAPI = async () => [];

  await import('../components/admin-main/admin-main.js?' + Date.now());
  assert(events['DOMContentLoaded']);
  events['DOMContentLoaded']();
  assert.equal(global.window.location.href, '../../index.html');
});


function makeEventEl(){
  return {
    events:{},
    style:{},
    classList:{ add(){}, remove(){} },
    addEventListener(ev,cb){ this.events[ev]=cb; },
    getEvent(ev){ return this.events[ev]; },
    appendChild(){},
    prepend(){},
    querySelector(){return null;},
    querySelectorAll(){return[];}
  };
}

test('initializes logout handler when token present', async () => {
  const events = {};
  const logoutBtn = makeEventEl();
  const elements = { loader: makeEventEl(), status: makeEventEl(), 'logout-btn': logoutBtn, 'html-editor': makeEventEl(), 'html-preview': makeEventEl() };
  global.document = {
    addEventListener: (ev, cb) => events[ev] = cb,
    getElementById: id => elements[id] || makeEventEl(),
    createElement: () => makeEventEl(),
    querySelectorAll: () => [],
    querySelector: () => null,
    body: Object.assign(makeEventEl(), { scrollHeight: 0 })
  };
  global.window = { location: { href: '' }, addEventListener(){}, innerHeight:0 };
  let removedToken = false;
  global.localStorage = { getItem: () => 'tok', removeItem: () => { removedToken = true; } };
  global.particlesJS = () => {};
  global.bootstrap = { Tooltip: function(){}, Modal: function(){ return { show(){} }; } };
  global.lucide = { createIcons(){} };
  global.VanillaTilt = { init(){} };
  global.window.fetchAPI = async () => [];
  global.fetch = async () => ({ ok:true, status:200, json: async () => ({ runs:[], state:'enabled' }) });
  await import('../components/admin-main/admin-main.js?' + Date.now());
  events['DOMContentLoaded']();
  assert(logoutBtn.getEvent('click'), 'logout click handler added');
  logoutBtn.getEvent('click')();
  assert(removedToken, 'token removed');
  assert.equal(global.window.location.href, '../../index.html');
});
