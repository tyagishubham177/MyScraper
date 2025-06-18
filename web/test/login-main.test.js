import test from 'node:test';
import assert from 'assert';

// capture event handler

test('registers DOMContentLoaded handler', async () => {
  const events = {};
  function makeEl() {
    return { style: {}, classList: { add(){}, remove(){} } };
  }
  global.document = {
    addEventListener: (ev, cb) => events[ev] = cb,
    getElementById: () => makeEl(),
    createElement: () => makeEl()
  };
  await import('../components/login/login-main.js?' + Date.now());
  assert(events['DOMContentLoaded']);
});

