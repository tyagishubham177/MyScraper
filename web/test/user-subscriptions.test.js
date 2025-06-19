import test from 'node:test';
import assert from 'assert';

function makeEl() {
  return {
    children: [],
    events: {},
    style: {},
    classList: {
      classes: [],
      add(...cls) { this.classes.push(...cls); },
      remove(...cls) { this.classes = this.classes.filter(c => !cls.includes(c)); },
      contains(cls) { return this.classes.includes(cls); }
    },
    dataset: {},
    appendChild(child) { this.children.push(child); },
    addEventListener(ev, cb) { this.events[ev] = cb; },
    getEvent(ev) { return this.events[ev]; },
    querySelector() { return null; },
    querySelectorAll(sel) { return sel === 'li' ? this.children : []; },
    setAttribute(name, val) {
      if (name.startsWith('data-')) {
        const key = name.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
        this.dataset[key] = val;
      } else {
        this[name] = val;
      }
    },
    getAttribute() { return null; },
    innerHTML: '',
    textContent: ''
  };
}

test('redirects to index when no email', async () => {
  global.localStorage = { getItem: () => null };
  global.window = { location: { href: '' } };
  global.document = { getElementById: () => null };
  global.fetch = async () => { throw new Error('fetch called'); };

  const mod = await import('../components/user-subscriptions/user-subscriptions.js?' + Date.now());
  await mod.initUserSubscriptionsUI();
  assert.equal(global.window.location.href, '../../index.html');
});

test('renders products and empty state', async () => {
  const subsList = makeEl();
  const allList = makeEl();
  const searchInput = makeEl();
  const collapse = makeEl();
  collapse.classList.contains = () => true;

  global.document = {
    getElementById(id) {
      if (id === 'user-subscribed-list') return subsList;
      if (id === 'all-products-list') return allList;
      if (id === 'product-search') return searchInput;
      if (id === 'allProductsListCollapse') return collapse;
      if (id === 'global-loader') return makeEl();
      return makeEl();
    },
    createElement: () => makeEl(),
  };
  global.localStorage = { getItem: key => key === 'userEmail' ? 'test@example.com' : null };
  global.window = { location: { href: '' } };
  global.lucide = { createIcons() {} };

  const responses = {
    '/api/recipients': [{ id: 1, email: 'test@example.com' }],
    '/api/products': [
      { id: 1, name: 'A', url: 'http://a' },
      { id: 2, name: 'B', url: 'http://b' }
    ],
    '/api/subscriptions?recipient_id=1': []
  };

  global.fetch = async (url) => ({ ok: true, status: 200, json: async () => responses[url] });

  const mod = await import('../components/user-subscriptions/user-subscriptions.js?' + Date.now());
  await mod.initUserSubscriptionsUI();

  assert.equal(subsList.children.length, 1);
  assert.ok(subsList.children[0].textContent.includes('empty'));
  assert.equal(allList.children.length, 2);
});

test('renders existing subscription', async () => {
  const subsList = makeEl();
  const allList = makeEl();
  const searchInput = makeEl();
  const collapse = makeEl();
  collapse.classList.contains = () => true;

  global.document = {
    getElementById(id) {
      if (id === 'user-subscribed-list') return subsList;
      if (id === 'all-products-list') return allList;
      if (id === 'product-search') return searchInput;
      if (id === 'allProductsListCollapse') return collapse;
      if (id === 'global-loader') return makeEl();
      return makeEl();
    },
    createElement: () => makeEl(),
  };
  global.localStorage = { getItem: key => key === 'userEmail' ? 'user@test.com' : null };
  global.window = { location: { href: '' } };
  global.lucide = { createIcons() {} };

  const responses = {
    '/api/recipients': [{ id: 2, email: 'user@test.com' }],
    '/api/products': [
      { id: 1, name: 'A', url: 'http://a' },
      { id: 2, name: 'B', url: 'http://b' }
    ],
    '/api/subscriptions?recipient_id=2': [
      { product_id: 1, start_time: '00:00', end_time: '23:59', paused: false }
    ]
  };

  global.fetch = async (url) => ({ ok: true, status: 200, json: async () => responses[url] });

  const mod = await import('../components/user-subscriptions/user-subscriptions.js?' + Date.now());
  await mod.initUserSubscriptionsUI();

  assert.equal(subsList.children.length, 1);
  assert.equal(subsList.children[0].dataset.productId, '1');
  assert.equal(allList.children.length, 1); // Only product 2 remains
});

function setupEnv() {
  const subsList = makeEl();
  const allList = makeEl();
  const searchInput = Object.assign(makeEl(), { value: '' });
  const collapse = makeEl();
  collapse.classList.contains = () => true;
  const loader = makeEl();

  global.document = {
    getElementById(id) {
      if (id === 'user-subscribed-list') return subsList;
      if (id === 'all-products-list') return allList;
      if (id === 'product-search') return searchInput;
      if (id === 'allProductsListCollapse') return collapse;
      if (id === 'global-loader') return loader;
      return makeEl();
    },
    createElement: tag => Object.assign(makeEl(), { tagName: tag, closest(sel){ return sel === 'li[data-product-id]' ? this : null; } })
  };
  global.window = { location: { href: '' }, lucide: { createIcons(){} } };
  global.localStorage = { getItem: key => key === 'userEmail' ? 'test@example.com' : null };
  return { subsList, allList, searchInput };
}

function trigger(el, ev, arg) {
  const cb = el.getEvent(ev);
  if (cb) return cb(arg);
}

test('subscribe button posts to API and updates lists', async () => {
  const { subsList, allList } = setupEnv();
  const calls = [];
  const responses = {
    '/api/recipients': [{ id: 1, email: 'test@example.com' }],
    '/api/products': [
      { id: 1, name: 'A', url: 'http://a' },
      { id: 2, name: 'B', url: 'http://b' }
    ],
    '/api/subscriptions?recipient_id=1': []
  };
  global.fetch = async (url, opts) => {
    calls.push({ url, opts });
    if (url === '/api/subscriptions' && opts && opts.method === 'POST') {
      return { ok: true, status: 200, json: async () => ({ product_id: 1, start_time: '00:00', end_time: '23:59', paused: false }) };
    }
    return { ok: true, status: 200, json: async () => responses[url] };
  };

  const mod = await import('../components/user-subscriptions/user-subscriptions.js?' + Date.now());
  await mod.initUserSubscriptionsUI();

  const li = allList.children[0];
  trigger(allList, 'click', {
    target: {
      closest(sel) {
        if (sel === '.sub-btn') return { closest: () => li };
        return null;
      }
    }
  });
  await new Promise(r => setImmediate(r));

  const post = calls.find(c => c.url === '/api/subscriptions' && c.opts && c.opts.method === 'POST');
  assert(post, 'POST call made');
  assert.equal(subsList.children.length, 1);
  assert.equal(subsList.children[0].dataset.productId, 1);
  assert.equal(allList.children.length, 1);
});

test('filterProducts hides unmatched items', async () => {
  const { allList, searchInput } = setupEnv();
  const responses = {
    '/api/recipients': [{ id: 1, email: 'test@example.com' }],
    '/api/products': [
      { id: 1, name: 'Alpha', url: 'http://a' },
      { id: 2, name: 'Beta', url: 'http://b' }
    ],
    '/api/subscriptions?recipient_id=1': []
  };
  global.fetch = async (url) => ({ ok: true, status: 200, json: async () => responses[url] });

  const mod = await import('../components/user-subscriptions/user-subscriptions.js?' + Date.now());
  await mod.initUserSubscriptionsUI();

  searchInput.value = 'beta';
  trigger(searchInput, 'input');
  const [liA, liB] = allList.children;
  assert(liA.classList.classes.includes('product-item-hidden'));
  assert(!liB.classList.classes.includes('product-item-hidden'));
});
