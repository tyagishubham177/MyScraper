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
      const all = [];
      const search = n => {
        if(sel.startsWith('.')) {
          const cls = sel.slice(1);
          if((n.className && n.className.split(' ').includes(cls)) || n.classList.classes.includes(cls)) all.push(n);
        } else if(sel.startsWith('#')) {
          if(n.id === sel.slice(1)) all.push(n);
        }
        n.children.forEach(c => search(c));
      };
      search(this);
      return all;
    },
    querySelector(sel){ return this.querySelectorAll(sel)[0] || null; },
    closest(sel){
      let cur = this;
      while(cur){
        if(sel.startsWith('.')) {
          const cls = sel.slice(1);
          if((cur.className && cur.className.split(' ').includes(cls)) || cur.classList.classes.includes(cls)) return cur;
        } else if(sel.startsWith('#')) {
          if(cur.id === sel.slice(1)) return cur;
        }
        cur = cur.parentNode;
      }
      return null;
    }
  };
  Object.defineProperty(el,'innerHTML',{ get(){ return this._innerHTML||''; }, set(v){ this._innerHTML=v; this.children=[]; } });
  return el;
}

test('openSubscriptionModal fetches data and renders', async () => {
  const modal = makeEl('div');
  const title = makeEl('h5');
  const pinEl = makeEl('p');
  const body = makeEl('div');
  const saveBtn = Object.assign(makeEl('button'), { disabled: true, innerHTML: '' });
  const map = { subscriptionModal: modal, subscriptionModalHeaderTitle: title, subscriptionModalPincode: pinEl, subscriptionModalBody: body, saveAllSubscriptionsBtn: saveBtn };
  global.document = { getElementById: id => map[id] || null, createElement: tag => makeEl(tag), body: makeEl('body') };
  global.window = {};
  global.localStorage = { getItem: () => null };
  global.fetch = async (url) => {
    if(url === '/api/products') return { ok: true, status: 200, json: async () => [{ id:1, name:'A' }, { id:2, name:'B' }] };
    if(url === '/api/subscriptions?recipient_id=1') return { ok: true, status: 200, json: async () => [] };
    throw new Error('unexpected url ' + url);
  };
  const mod = await import('../components/subscription/subscription-modal.js?' + Date.now());
  await mod.openSubscriptionModal(1, 'Bob', '999999');
  assert.equal(title.textContent, 'Manage Subscriptions for Bob');
  assert.equal(pinEl.textContent, 'Pincode: 999999');
  assert.equal(modal.style.display, 'block');
  assert.equal(body.children.length, 2);
  assert.equal(saveBtn.disabled, false);
});

test('initSubscriptionsUI creates modal and save button', async () => {
  const map = {};
  const body = makeEl('body');
  body.appendChild = el => { body.children.push(el); if(el.id) map[el.id] = el; };
  const modal = makeEl('div');
  const footer = makeEl('div');
  footer.className = 'modal-footer';
  footer.appendChild = el => { footer.children.push(el); if(el.id) map[el.id] = el; el.parentNode = footer; };
  const modalBody = makeEl('div');
  modalBody.id = 'subscriptionModalBody';
  modalBody.addEventListener = (ev, cb) => { modalBody.events[ev] = cb; };
  modalBody.getEvent = ev => modalBody.events[ev];
  modal.querySelector = sel => sel === '.modal-footer' ? footer : null;
  let firstCall = true;
  global.document = {
    getElementById: id => map[id] || null,
    createElement: tag => { if(tag==='div' && firstCall){ firstCall=false; return modal; } return makeEl(tag); },
    body,
    querySelector: () => null
  };
  map['subscriptionModalBody'] = modalBody;
  global.window = {};
  const mod = await import('../components/subscription/subscription-modal.js?' + Date.now());
  mod.initSubscriptionsUI();
  map['subscriptionModal'] = modal;
  const saveBtn = map['saveAllSubscriptionsBtn'];
  assert(saveBtn, 'save button created');
  assert(saveBtn.getEvent('click'), 'click handler attached');
});


test('saving subscription changes triggers API calls', async () => {
  const map = {};
  const body = makeEl('body');
  body.appendChild = el => { body.children.push(el); if(el.id) map[el.id] = el; };
  const modal = makeEl('div');
  const footer = makeEl('div');
  footer.className = 'modal-footer';
  footer.appendChild = el => { footer.children.push(el); if(el.id) map[el.id] = el; el.parentNode = footer; };
  const modalBody = makeEl('div');
  modalBody.id = 'subscriptionModalBody';
  modalBody.addEventListener = (ev, cb) => { modalBody.events[ev] = cb; };
  modalBody.getEvent = ev => modalBody.events[ev];
  modal.querySelector = sel => sel === '.modal-footer' ? footer : null;
  let firstCall = true;
  global.document = {
    getElementById: id => map[id] || null,
    createElement: tag => { if(tag==='div' && firstCall){ firstCall=false; return modal; } return makeEl(tag); },
    body,
    querySelector: sel => null
  };
  map['subscriptionModalBody'] = modalBody;
  global.window = {};
  global.localStorage = { getItem: () => null };
  const fetchCalls = [];
  global.fetch = async (url, options = {}) => {
    if(url === '/api/products') return { ok: true, status: 200, json: async () => [{ id:1, name:'A' }, { id:2, name:'B' }] };
    if(url === '/api/subscriptions?recipient_id=1') return { ok: true, status: 200, json: async () => [{ product_id:1, start_time:'00:00', end_time:'23:59' }] };
    if(url === '/api/subscriptions') {
      fetchCalls.push({ method: options.method, body: options.body });
      return { ok: true, status: 200, json: async () => ({}) };
    }
    throw new Error('unexpected url ' + url);
  };

  const mod = await import('../components/subscription/subscription-modal.js?' + Date.now());
  mod.initSubscriptionsUI();
  map['subscriptionModal'] = modal;
  const header = makeEl('h5');
  header.id = 'subscriptionModalHeaderTitle';
  const pinEl2 = makeEl('p');
  map['subscriptionModalHeaderTitle'] = header;
  map['subscriptionModalPincode'] = pinEl2;
  const bodyEl = modalBody;
  body.appendChild(bodyEl);
  const saveBtn = map['saveAllSubscriptionsBtn'];

  await mod.openSubscriptionModal(1, 'Bob', '999999');

  const items = bodyEl.children;
  const first = items[0];
  const second = items[1];
  const cb1 = first.querySelector('.subscription-toggle');
  const cb2 = second.querySelector('.subscription-toggle');
  const start1 = first.querySelector('.sub-time-start');
  const end1 = first.querySelector('.sub-time-end');
  cb1.checked = false;
  cb2.checked = true;
  bodyEl.getEvent('change')({ target: cb1 });

  await saveBtn.getEvent('click')();

  assert.equal(fetchCalls.length, 2);
  const methods = fetchCalls.map(c => c.method).sort();
  assert.deepEqual(methods, ['DELETE', 'POST']);
});

