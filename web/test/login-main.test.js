import test from 'node:test';
import assert from 'assert';

// capture event handler

test('registers DOMContentLoaded handler', async () => {
  const events = {};
  global.document = { addEventListener: (ev, cb) => events[ev] = cb };
  await import('../components/login/login-main.js?' + Date.now());
  assert(events['DOMContentLoaded']);
});

