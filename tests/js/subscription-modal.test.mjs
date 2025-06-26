import assert from 'assert';
import fs from 'fs/promises';

class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.style = {};
    this.classList = new Set();
    this.parent = null;
    this.disabled = false;
  }
  appendChild(el) { el.parent = this; this.children.push(el); }
  closest(sel) { let el=this; while(el){ if(el.matches(sel)) return el; el=el.parent;} return null; }
  matches(sel){ if(sel.startsWith('.')) return this.classList.has(sel.slice(1)); if(sel.startsWith('#')) return this.id===sel.slice(1); return false; }
  querySelector(sel){ const search=node=>{ for(const c of node.children){ if(c.matches(sel)) return c; const r=search(c); if(r) return r; } return null; }; return search(this); }
}

async function loadFunction(){
  let code = await fs.readFile('web/components/subscription/subscription-modal.js','utf8');
  code = code.replace(/import[^;]+subscription-helpers[^;]+;/, 'const updateSaveButtonStateHelper = global.updateSaveButtonStateHelper;');
  code = code.replace(/import[^;]+utils[^;]+;/, '');
  code += '\nexport { handleSubscriptionToggle };';
  const b64 = Buffer.from(code).toString('base64');
  const mod = await import('data:text/javascript;base64,' + b64);
  return mod.handleSubscriptionToggle;
}

async function testHandleSubscriptionToggle(){
  global.updateSaveButtonStateHelper = () => { updateCalled = true; };
  global.initialSubscriptionDataForModal = '';
  const handleSubscriptionToggle = await loadFunction();
  let updateCalled = false;
  const item = new Element('div');
  item.classList.add('list-group-item');
  const checkbox = new Element('input');
  checkbox.classList.add('subscription-toggle');
  checkbox.checked = true;
  const start = new Element('input');
  start.classList.add('sub-time-start');
  const end = new Element('input');
  end.classList.add('sub-time-end');
  item.appendChild(checkbox);
  item.appendChild(start);
  item.appendChild(end);

  const event = { target: checkbox };
  handleSubscriptionToggle(event);
  assert.strictEqual(start.disabled, false);
  assert.strictEqual(end.disabled, false);
  assert.ok(updateCalled);

  updateCalled = false;
  checkbox.checked = false;
  handleSubscriptionToggle(event);
  assert.strictEqual(start.disabled, true);
  assert.strictEqual(end.disabled, true);
  assert.ok(updateCalled);
}

await testHandleSubscriptionToggle();
console.log('handleSubscriptionToggle tests passed');
