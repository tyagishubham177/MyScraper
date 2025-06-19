import test from 'node:test';
import assert from 'assert';

function makeEl() {
  return {
    children: [],
    style: {},
    classList: {
      classes: [],
      add(...cls) { this.classes.push(...cls); },
      remove(...cls) { this.classes = this.classes.filter(c => !cls.includes(c)); }
    },
    dataset: {},
    addEventListener(ev, cb) { this.events ??= {}; this.events[ev] = cb; },
    appendChild(child) { this.children.push(child); },
    setAttribute(name, val) {
      if (name.startsWith('data-')) {
        const key = name.slice(5).replace(/-([a-z])/g, (_,c)=>c.toUpperCase());
        this.dataset[key] = val;
      } else {
        this[name] = val;
      }
    },
    getEvent(ev) { return this.events?.[ev]; },
    closest(sel) {
      if (sel.startsWith('.')) {
        const cls = sel.slice(1);
        return this.classList.classes.includes(cls) ? this : null;
      }
      if (sel.includes('.')) {
        const cls = sel.split('.').pop();
        return this.classList.classes.includes(cls) ? this : null;
      }
      return null;
    }
  };
}

function setupEnv() {
  const elements = {
    'add-product-btn': makeEl(),
    'products-list': makeEl(),
    'product-name': Object.assign(makeEl(), { value: '' }),
    'product-url': Object.assign(makeEl(), { value: '' }),
    'add-product-error-message': makeEl(),
    'edit-product-id': Object.assign(makeEl(), { value: '' }),
    'edit-product-name': Object.assign(makeEl(), { value: '' }),
    'edit-product-url': Object.assign(makeEl(), { value: '' }),
    'edit-product-error-message': makeEl(),
    'save-product-changes-btn': makeEl()
  };
  elements['editProductModal'] = Object.assign(makeEl(), {
    querySelector(sel) {
      if (sel === '#edit-product-id') return elements['edit-product-id'];
      if (sel === '#edit-product-name') return elements['edit-product-name'];
      if (sel === '#edit-product-url') return elements['edit-product-url'];
      return null;
    }
  });
  const document = {
    getElementById: id => elements[id] || null,
    createElement: () => makeEl(),
    addEventListener() {},
    body: makeEl()
  };
  global.document = document;
  global.window = { fetchAPI: async () => [], lucide: { createIcons(){} } };
  global.localStorage = { getItem(){ return null; } };
  global.alert = () => {};
  global.confirm = () => true;
  return { elements };
}

async function loadModule() {
  return await import('../components/products-ui/products-ui.js?' + Date.now());
}

function trigger(el, ev, arg) {
  const cb = el.getEvent(ev);
  if (cb) return cb(arg);
}

// --- Tests ---

test('initProductsUI attaches handler and fetches list', async () => {
  const env = setupEnv();
  let fetchCalled = false;
  global.window.fetchAPI = async () => { fetchCalled = true; return []; };
  const mod = await loadModule();
  mod.initProductsUI();
  assert(env.elements['add-product-btn'].events.click, 'click handler added');
  await Promise.resolve();
  assert(fetchCalled, 'fetchAPI called');
});

test('handleAddProduct successful submission', async () => {
  const env = setupEnv();
  const calls = [];
  global.window.fetchAPI = async (url, opts) => { calls.push({ url, opts }); return []; };
  const mod = await loadModule();
  mod.initProductsUI();
  env.elements['product-name'].value = 'Prod';
  env.elements['product-url'].value = 'http://x';
  await trigger(env.elements['add-product-btn'], 'click', { preventDefault(){} });
  const postCall = calls.find(c => c.opts && c.opts.method === 'POST');
  assert(postCall, 'POST call made');
  assert.equal(postCall.url, '/api/products');
  assert.equal(env.elements['product-name'].value, '');
  assert.equal(env.elements['product-url'].value, '');
});

test('handleAddProduct shows error for missing fields', async () => {
  const env = setupEnv();
  const mod = await loadModule();
  mod.initProductsUI();
  env.elements['product-name'].value = '';
  env.elements['product-url'].value = '';
  await trigger(env.elements['add-product-btn'], 'click', { preventDefault(){} });
  assert.equal(env.elements['add-product-error-message'].innerHTML, 'Please enter both product name and URL.');
});

test('renderProductsList creates list items', async () => {
  const env = setupEnv();
  global.window.fetchAPI = async () => [{ id: 1, name: 'A', url: 'http://a' }];
  const mod = await loadModule();
  mod.initProductsUI();
  await Promise.resolve();
  const list = env.elements['products-list'];
  assert.equal(list.children.length, 1);
  assert.equal(list.children[0].dataset.productId, 1);
});

test('delete button calls API and refreshes subscriptions', async () => {
  const env = setupEnv();
  const calls = [];
  global.window.fetchAPI = async (url, opts) => { calls.push({ url, opts }); };
  let subId = null;
  global.window.selectedRecipient = { id: 7 };
  global.window.loadSubscriptionsForRecipient = id => { subId = id; };
  const mod = await loadModule();
  mod.initProductsUI();
  const btn = makeEl();
  btn.classList.add('delete-product-btn');
  btn.dataset.productId = '5';
  btn.closest = sel => sel === 'button.delete-product-btn' ? btn : null;
  await trigger(env.elements['products-list'], 'click', { target: btn });
  await Promise.resolve();
  const del = calls.find(c => c.opts && c.opts.method === 'DELETE');
  assert(del, 'DELETE call made');
  assert.equal(del.url, '/api/products?id=5');
  assert.equal(subId, 7);
});

test('edit modal populates fields on show', async () => {
  const env = setupEnv();
  const mod = await loadModule();
  mod.initProductsUI();
  const modal = env.elements['editProductModal'];
  const handler = modal.getEvent('show.bs.modal');
  const button = {
    getAttribute(name) {
      return { 'data-product-id': '9', 'data-product-name': 'N', 'data-product-url': 'http://n' }[name];
    }
  };
  handler({ relatedTarget: button });
  assert.equal(env.elements['edit-product-id'].value, '9');
  assert.equal(env.elements['edit-product-name'].value, 'N');
  assert.equal(env.elements['edit-product-url'].value, 'http://n');
});

test('save changes sends PUT and hides modal', async () => {
  const env = setupEnv();
  const calls = [];
  global.window.fetchAPI = async (url, opts) => { calls.push({ url, opts }); };
  let hidden = false;
  global.bootstrap = { Modal: class { static getInstance(){ return { hide(){ hidden = true; } }; } } };
  env.elements['edit-product-id'].value = '4';
  env.elements['edit-product-name'].value = 'New';
  env.elements['edit-product-url'].value = 'http://new';
  const mod = await loadModule();
  mod.initProductsUI();
  await trigger(env.elements['save-product-changes-btn'], 'click');
  await Promise.resolve();
  const put = calls.find(c => c.opts && c.opts.method === 'PUT');
  assert(put, 'PUT call made');
  assert.equal(put.url, '/api/products?id=4');
  assert(hidden, 'modal hidden');
});

test('fallback fetchAPI adds token and parses errors', async () => {
  const env = setupEnv();
  delete global.window.fetchAPI;
  global.localStorage.getItem = () => 'tok';
  let passedOpts;
  global.fetch = async () => ({ ok: false, status: 400, json: async () => ({ message: 'boom' }) });
  const mod = await loadModule();
  let error;
  try {
    await global.window.fetchAPI('/x', passedOpts = { headers: {} });
  } catch (e) {
    error = e;
  }
  assert(error instanceof Error, 'error thrown');
  assert.equal(passedOpts.headers.Authorization, 'Bearer tok');
  assert.equal(error.message, 'boom');
});
