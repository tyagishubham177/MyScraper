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
    querySelector(){ return null; },
    querySelectorAll(){ return []; }
  };
  Object.defineProperty(el,'innerHTML',{ get(){ return this._innerHTML||''; }, set(v){ this._innerHTML=v; this.children=[]; } });
  return el;
}

// --- Tests ---

test('showToastNotification adds toast element', async () => {
  let container = null;
  const document = {
    querySelector: sel => sel === '.toast-container' ? container : null,
    createElement: () => makeEl('div'),
    body: { appendChild(el){ container = el; } }
  };
  global.document = document;
  global.setTimeout = (fn) => { fn(); return 1; };

  const { showToastNotification } = await import('../components/subscription/subscription-helpers.js?' + Date.now());
  showToastNotification('hi', 'success', 10);
  assert(container, 'container created');
  assert.equal(container.children.length, 1);
  const toast = container.children[0];
  assert.equal(toast.textContent, 'hi');
  assert(toast.classList.classes.includes('success'));
});

function setupFormEnv() {
  const saveBtn = makeEl('button');
  saveBtn.classList.add('btn','btn-outline-primary');
  const checkbox = Object.assign(makeEl('input'), { checked: true, dataset: { productId: '1' } });
  const startInput = Object.assign(makeEl('input'), { value: '00:00' });
  const endInput = Object.assign(makeEl('input'), { value: '23:59' });
  const item = makeEl('div');
  item.querySelector = sel => {
    if(sel === '.subscription-toggle') return checkbox;
    if(sel === '.sub-time-start') return startInput;
    if(sel === '.sub-time-end') return endInput;
    return null;
  };
  const modalBody = makeEl('div');
  modalBody.querySelectorAll = sel => sel === '.list-group-item' ? [item] : [];
  global.document = {
    getElementById: id => id === 'subscriptionModalBody' ? modalBody : id === 'saveAllSubscriptionsBtn' ? saveBtn : null
  };
  return { saveBtn, checkbox, startInput };
}

test('form state helpers detect changes', async () => {
  const env = setupFormEnv();
  const helpers = await import('../components/subscription/subscription-helpers.js?' + Date.now());
  const state = helpers.storeInitialFormState();
  assert.equal(state, '{"1":{"subscribed":true,"start":"00:00","end":"23:59","paused":false}}');
  helpers.updateSaveButtonState(state);
  assert(env.saveBtn.classList.classes.includes('btn-outline-primary'));
  env.startInput.value = '01:00';
  helpers.updateSaveButtonState(state);
  assert(env.saveBtn.classList.classes.includes('btn-primary'));
  env.startInput.value = '00:00';
  helpers.updateSaveButtonState(state);
  assert(env.saveBtn.classList.classes.includes('btn-outline-primary'));
});
