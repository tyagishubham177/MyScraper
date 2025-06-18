import test from 'node:test';
import assert from 'assert';

// Helper to create stub element
function makeEl() {
  return {
    addEventListener: () => {},
    style: {},
    classList: { add() {}, remove() {} }
  };
}

test('initIcons runs lucide and tooltips', async () => {
  let createCalled = 0;
  global.lucide = { createIcons: () => { createCalled++; } };
  let tooltipCount = 0;
  global.bootstrap = { Tooltip: function(el){ tooltipCount++; } };

  const tooltipEls = [makeEl(), makeEl()];
  const collapseEl = { addEventListener() {} };
  const events = {};
  global.window = {
    innerHeight: 50,
    addEventListener: (ev, cb) => { if (ev === 'load') cb(); events[ev] = cb; }
  };
  global.document = {
    querySelectorAll: (sel) => {
      if (sel === '[data-bs-toggle="tooltip"]') return tooltipEls;
      if (sel === '.accordion-collapse') return [collapseEl];
      return [];
    },
    body: {
      scrollHeight: 100,
      classList: { add(cls){ this.added = cls; }, remove(){} }
    }
  };

  const { initIcons } = await import('../components/icons/icons.js?' + Date.now());
  initIcons();
  assert.equal(createCalled, 1);
  assert.equal(tooltipCount, tooltipEls.length);
  assert.equal(global.document.body.classList.added, 'is-scrollable');
});

