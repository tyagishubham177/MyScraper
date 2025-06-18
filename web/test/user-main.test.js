import test from 'node:test';
import assert from 'assert';
import fs from 'fs/promises';

// Helper to mock modules used by the inline script
async function mockModules(t) {
  await t.mock.module('../components/particles-config/particles-config.js', { initParticles(){ } });
  await t.mock.module('../components/icons/icons.js', { initIcons(){ } });
  await t.mock.module('../components/ui/ui.js', { initBackground(){ } });
  await t.mock.module('../components/user-subscriptions/user-subscriptions.js', { initUserSubscriptionsUI(){ } });
  await t.mock.module('../components/utils/utils.js', {
    showGlobalLoader(){},
    hideGlobalLoader(){},
    escapeHTML: s => s
  });
}

test('user-main registers DOMContentLoaded handler', async t => {
  await mockModules(t);
  const html = await fs.readFile('../components/user-main/user.html', 'utf8');
  const match = html.match(/<script type="module">([\s\S]*?)<\/script>/);
  const script = match ? match[1] : '';
  const events = {};
  global.document = { addEventListener: (ev, cb) => events[ev] = cb };
  global.window = {};
  global.localStorage = { getItem: () => 'test@example.com', setItem(){}, removeItem(){} };
  global.bootstrap = { Modal: { getInstance: () => ({ hide(){} }), getOrCreateInstance: () => ({ show(){}, hide(){} }) } };
  global.fetch = async () => ({ text: async () => '' });
  const dataUrl = 'data:text/javascript;base64,' + Buffer.from(script).toString('base64');
  await import(dataUrl + '?cache=' + Date.now());
  assert(events['DOMContentLoaded']);
});
