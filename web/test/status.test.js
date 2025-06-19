import test from 'node:test';
import assert from 'assert';

function makeEl(){
  return {
    style:{},
    classList:{
      classes:[],
      add(...c){ this.classes.push(...c); },
      remove(...c){ this.classes = this.classes.filter(x=>!c.includes(x)); }
    },
    textContent:'',
  };
}

test('showLoader and hideLoader update elements', async () => {
  const loader = makeEl();
  const status = makeEl();
  global.document = { getElementById: id => ({loader,status}[id]) };
  const mod = await import('../components/status/status.js?' + Date.now());
  mod.showLoader();
  assert.equal(loader.style.display, 'inline-block');
  assert(status.classList.classes.includes('status-loading-pulse'));
  mod.hideLoader();
  assert.equal(loader.style.display, 'none');
  assert(!status.classList.classes.includes('status-loading-pulse'));
});

test('fetchStatus populates status text', async () => {
  const loader = makeEl();
  const status = makeEl();
  global.document = { getElementById: id => ({loader,status}[id]) };
  global.fetch = async () => ({ ok:true, status:200, json: async () => ({ state:'enabled' }) });
  global.localStorage = { getItem: () => 'tok' };
  const mod = await import('../components/status/status.js?' + Date.now());
  await mod.fetchStatus();
  assert.equal(status.textContent, 'enabled');
  assert.equal(loader.style.display, 'none');
  assert(status.classList.classes.includes('bg-success-subtle'));
});
