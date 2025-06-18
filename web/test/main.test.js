import test from 'node:test';
import assert from 'assert';

function makeEl() {
  return {
    children: [],
    appendChild(child){ this.children.push(child); },
    addEventListener(){},
    querySelector(){ return null; },
    querySelectorAll(){ return []; },
    style:{},
    classList:{ add(){}, remove(){} }
  };
}

test('registers DOMContentLoaded handler', async () => {
  const events = {};
  global.document = {
    addEventListener: (ev, cb) => events[ev] = cb,
    getElementById: () => makeEl(),
    createElement: () => makeEl(),
    body: makeEl(),
    querySelector: () => makeEl(),
    querySelectorAll: () => []
  };
  global.window = {};
  await import('../components/main/main.js?' + Date.now());
  assert(events['DOMContentLoaded']);
});

