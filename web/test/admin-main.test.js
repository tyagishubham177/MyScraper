import test from 'node:test';
import assert from 'assert';

function makeEl() {
  return {
    addEventListener(){},
    appendChild(){},
    prepend(){},
    querySelector(){ return null; },
    querySelectorAll(){ return []; },
    style: {},
    classList: { add(){}, remove(){} }
  };
}

test('handler redirects to index when no token', async () => {
  const events = {};
  const elements = { loader: makeEl(), status: makeEl() };
  global.document = {
    addEventListener: (ev, cb) => events[ev] = cb,
    getElementById: id => elements[id] || makeEl(),
    createElement: () => makeEl(),
    querySelectorAll: () => [],
    body: Object.assign(makeEl(), { scrollHeight: 0 })
  };
  global.window = { location: { href: '' } };
  global.localStorage = { getItem: () => null };

  await import('../components/admin-main/admin-main.js?' + Date.now());
  assert(events['DOMContentLoaded']);
  events['DOMContentLoaded']();
  assert.equal(global.window.location.href, '../../index.html');
});

