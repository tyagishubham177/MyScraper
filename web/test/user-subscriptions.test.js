import test from 'node:test';
import assert from 'assert';

function makeEl() {
  return {
    children: [],
    appendChild(child) { this.children.push(child); },
    addEventListener() {},
    querySelector() { return null; },
    querySelectorAll() { return this.children; },
    classList: { add(){}, remove(){}, contains(){ return true; } },
    style: {},
    dataset: {},
    setAttribute() {},
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
