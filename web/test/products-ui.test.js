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
    getEvent(ev) { return this.events?.[ev]; }
  };
}

function setupEnv() {
  const elements = {
    'add-product-btn': makeEl(),
    'products-list': makeEl(),
    'product-name': Object.assign(makeEl(), { value: '' }),
    'product-url': Object.assign(makeEl(), { value: '' }),
    'add-product-error-message': makeEl()
  };
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
