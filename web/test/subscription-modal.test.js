import test from 'node:test';
import assert from 'assert';

function makeEl(tag='div') {
  const el = {
    tagName: tag.toUpperCase(),
    children: [],
    style: {},
    className: '',
    classList: {
      classes: [],
      add(...cls){ this.classes.push(...cls); },
      remove(...cls){ this.classes = this.classes.filter(c => !cls.includes(c)); },
      contains(cls){ return this.classes.includes(cls); }
    },
    dataset: {},
    events: {},
    appendChild(child){ this.children.push(child); child.parentNode = this; },
    removeChild(child){ this.children = this.children.filter(c => c!==child); },
    addEventListener(ev, cb){ this.events[ev] = cb; },
    getEvent(ev){ return this.events[ev]; },
    setAttribute(name, val){
      if(name === 'id') this.id = val;
      else if(name.startsWith('data-')) {
        const key = name.slice(5).replace(/-([a-z])/g, (_,c)=>c.toUpperCase());
        this.dataset[key] = val;
      } else { this[name] = val; }
    },
    getAttribute(name){ return this[name]; },
    textContent: '',
    querySelectorAll(sel){
      if(sel.startsWith('.')) {
        const cls = sel.slice(1);
        const all = [];
        const search = n => { if(n.className && n.className.split(' ').includes(cls) || n.classList.classes.includes(cls)) all.push(n); n.children.forEach(c=>search(c)); };
        search(this);
        return all;
      }
      return [];
    },
    querySelector(sel){ return this.querySelectorAll(sel)[0] || null; }
  };
  Object.defineProperty(el,'innerHTML',{ get(){ return this._innerHTML||''; }, set(v){ this._innerHTML=v; this.children=[]; } });
  return el;
}

test('openSubscriptionModal fetches data and renders', async () => {
  const modal = makeEl('div');
  const title = makeEl('h5');
  const body = makeEl('div');
  const saveBtn = Object.assign(makeEl('button'), { disabled: true, innerHTML: '' });
  const map = { subscriptionModal: modal, subscriptionModalHeaderTitle: title, subscriptionModalBody: body, saveAllSubscriptionsBtn: saveBtn };
  global.document = { getElementById: id => map[id] || null, createElement: tag => makeEl(tag), body: makeEl('body') };
  global.window = {};
  global.localStorage = { getItem: () => null };
  global.fetch = async (url) => {
    if(url === '/api/products') return { ok: true, status: 200, json: async () => [{ id:1, name:'A' }, { id:2, name:'B' }] };
    if(url === '/api/subscriptions?recipient_id=1') return { ok: true, status: 200, json: async () => [] };
    throw new Error('unexpected url ' + url);
  };
  const mod = await import('../components/subscription/subscription-modal.js?' + Date.now());
  await mod.openSubscriptionModal(1, 'Bob');
  assert.equal(title.textContent, 'Manage Subscriptions for Bob');
  assert.equal(modal.style.display, 'block');
  assert.equal(body.children.length, 2);
  assert.equal(saveBtn.disabled, false);
});
