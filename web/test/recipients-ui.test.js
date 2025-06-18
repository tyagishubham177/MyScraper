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
    'add-recipient-btn': makeEl(),
    'recipients-list': makeEl(),
    'recipient-email': Object.assign(makeEl(), { value: '' }),
    'add-recipient-error-message': makeEl(),
    'recipient-subscriptions-section': makeEl(),
    'close-subscriptions-btn': makeEl()
  };
  const document = {
    getElementById: id => elements[id] || null,
    createElement: () => makeEl(),
    addEventListener() {},
    body: makeEl()
  };
  global.document = document;
  global.window = { lucide: { createIcons(){} } };
  global.localStorage = { getItem(){ return null; } };
  global.alert = () => {};
  global.confirm = () => true;
  return { elements };
}

async function loadModule() {
  return await import('../components/recipients-ui/recipients-ui.js?' + Date.now());
}

function trigger(el, ev, arg) {
  const cb = el.getEvent(ev);
  if (cb) return cb(arg);
}

// --- Tests ---

test('initRecipientsUI attaches handler and fetches list', async () => {
  const env = setupEnv();
  let called = false;
  global.fetch = async (url) => { if(url === '/api/recipients') called = true; return { ok:true, status:200, json: async () => [] }; };
  const mod = await loadModule();
  mod.initRecipientsUI();
  assert(env.elements['add-recipient-btn'].events.click, 'click handler added');
  await Promise.resolve();
  assert(called, 'fetch called');
});

test('handleAddRecipient successful submission', async () => {
  const env = setupEnv();
  let calls = [];
  global.fetch = async (url, opts) => { calls.push({url, opts}); return { ok:true, status:200, json: async () => [] }; };
  const mod = await loadModule();
  mod.initRecipientsUI();
  await Promise.resolve(); // initial fetch
  calls = [];
  env.elements['recipient-email'].value = 'foo@example.com';
  await trigger(env.elements['add-recipient-btn'], 'click', { preventDefault(){} });
  await Promise.resolve();
  const post = calls.find(c => c.opts && c.opts.method === 'POST');
  assert(post, 'POST made');
  assert.equal(post.url, '/api/recipients');
  assert.equal(env.elements['recipient-email'].value, '');
});

test('handleAddRecipient shows error for empty email', async () => {
  const env = setupEnv();
  global.fetch = async () => ({ ok:true, status:200, json: async () => [] });
  const mod = await loadModule();
  mod.initRecipientsUI();
  env.elements['recipient-email'].value = '';
  await trigger(env.elements['add-recipient-btn'], 'click', { preventDefault(){} });
  assert.equal(env.elements['add-recipient-error-message'].innerHTML, 'Please enter an email address.');
});

test('renderRecipientsList populates DOM', async () => {
  const env = setupEnv();
  global.fetch = async () => ({ ok:true, status:200, json: async () => [{ id: 1, email: 'a@b.com' }] });
  let created = false;
  global.window.lucide.createIcons = () => { created = true; };
  const mod = await loadModule();
  mod.initRecipientsUI();
  await Promise.resolve();
  const list = env.elements['recipients-list'];
  assert.equal(list.children.length, 1);
  assert.equal(list.children[0].dataset.recipientId, 1);
  assert(created, 'icons created');
});
