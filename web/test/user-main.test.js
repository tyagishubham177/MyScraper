import test from 'node:test';
import assert from 'assert';
import fs from 'fs/promises';
import vm from 'vm';

function runInlineScript(html, globals) {
  const match = html.match(/<script type="module">([\s\S]*?)<\/script>/);
  if (!match) return;
  let script = match[1];
  script = script.replace(/^\s*import .*?;\n/gm, '');
  const context = { ...globals };
  vm.runInNewContext(script, context, { filename: 'user-main-inline.js' });
}

test('user-main registers DOMContentLoaded handler', async () => {
  const html = await fs.readFile('./components/user-main/user.html', 'utf8');
  const events = {};
  const globals = {
    document: {
      addEventListener: (ev, cb) => (events[ev] = cb),
      getElementById: () => ({ addEventListener() {}, classList: { remove(){}, add(){} } })
    },
    window: {},
    localStorage: { getItem: () => 'test@example.com', setItem() {}, removeItem() {} },
    bootstrap: { Modal: { getInstance: () => ({ hide() {} }), getOrCreateInstance: () => ({ show() {}, hide() {} }) } },
    fetch: async () => ({ text: async () => '' })
  };
  runInlineScript(html, globals);
  assert(events['DOMContentLoaded']);
});
