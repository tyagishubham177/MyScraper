import test from 'node:test';
import assert from 'assert';

function makeEl(){
  const el = {
    style:{},
    classList:{ classes:[], add(...c){ this.classes.push(...c); }, remove(...c){ this.classes=this.classes.filter(x=>!c.includes(x)); } },
    events:{},
    children:[],
    addEventListener(ev,cb){ this.events[ev]=cb; },
    getEvent(ev){ return this.events[ev]; },
    appendChild(child){ this.children.push(child); },
    querySelector(){ return null; },
    querySelectorAll(){ return []; }
  };
  Object.defineProperty(el, 'innerHTML', { get(){ return this._html || ''; }, set(v){ this._html=v; } });
  return el;
}

function setupBase(){
  const elements = {
    'refresh': makeEl(),
    'refresh-runs': makeEl(),
    'loader': makeEl(),
    'status': makeEl(),
    'runsAccordion': makeEl(),
    'particles-js-bg': makeEl(),
    'recipientManagementCollapse': makeEl(),
    'productManagementCollapse': makeEl()
  };
  const recBtn = makeEl();
  recBtn.querySelector = () => makeEl();
  const prodBtn = makeEl();
  prodBtn.querySelector = () => makeEl();
  global.document = {
    getElementById: id => elements[id] || makeEl(),
    createElement: () => makeEl(),
    querySelector: sel => {
      if(sel === '[data-bs-target="#recipientManagementCollapse"]') return recBtn;
      if(sel === '[data-bs-target="#productManagementCollapse"]') return prodBtn;
      return null;
    },
    querySelectorAll: () => [] ,
    body: makeEl()
  };
  global.window = { lucide:{ createIcons(){} }, addEventListener(){}, innerHeight:0 };
  global.bootstrap = { Tooltip: function(){} };
  global.particlesJS = () => {};
  global.VanillaTilt = { init(){} };
  global.fetch = async () => ({ ok:true, status:200, json: async () => ({ runs: [], state: 'enabled' }) });
  global.localStorage = { getItem: () => null };
  return { elements, recBtn, prodBtn };
}

test('initBackground sets gradient', async () => {
  const el = makeEl();
  global.document = { getElementById: () => el };
  const mod = await import('../components/ui/ui.js?' + Date.now());
  mod.initBackground();
  assert(el.style.backgroundImage);
  assert.equal(el.style.animation, 'none');
});

test('initBackground logs error when missing', async () => {
  let logged = false;
  global.document = { getElementById: () => null };
  global.console = { error(){ logged = true; } };
  const mod = await import('../components/ui/ui.js?' + Date.now());
  mod.initBackground();
  assert(logged);
});

test('initPage attaches handlers and calls helpers', async () => {
  const { elements, recBtn, prodBtn } = setupBase();
  let fetchCount = 0;
  global.fetch = async () => { fetchCount++; return { ok:true, status:200, json: async () => ({ runs: [], state:'enabled' }) }; };
  const mod = await import('../components/ui/ui.js?' + Date.now());
  await mod.initPage();
  assert(elements['refresh'].getEvent('click'), 'refresh handler');
  assert(elements['refresh-runs'].getEvent('click'), 'refresh runs handler');
  assert(recBtn.getEvent('show.bs.collapse'), 'collapse handler');
  assert(fetchCount > 0, 'fetch called');
});
