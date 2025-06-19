import test from 'node:test';
import assert from 'assert';

function makeEl() {
  let html = '';
  return {
    dataset: {},
    classList: { classes: [], add(c){ this.classes.push(c); } },
    children: [],
    events: {},
    addEventListener(ev, cb){ this.events[ev] = cb; },
    getEvent(ev){ return this.events[ev]; },
    appendChild(child){ this.children.push(child); },
    querySelector(sel){ return this.children.find(c => '#' + (c.id||'') === sel); },
    get innerHTML(){ return html; },
    set innerHTML(v){ html = v; },
    textContent: ''
  };
}

async function loadModule() {
  return await import('../components/runs/runs.js?' + Date.now());
}

test('fetchScraperDecisions parses log entries from zip', async () => {
  const { fetchScraperDecisions } = await loadModule();

  const logText = "✅ Product 'A' (URL: http://a) is IN STOCK.\n" +
                  "❌ Product 'B' (URL: http://b) is OUT OF STOCK.";

  global.localStorage = { getItem: () => 'tok' };
  global.fetch = async (url, opts) => ({
    ok: true,
    blob: async () => 'blob'
  });
  global.JSZip = {
    loadAsync: async () => ({
      files: {
        'run_stock_checker.log': { async: async () => logText }
      }
    })
  };

  const res = await fetchScraperDecisions('1');
  assert.deepEqual(res, [
    { name: 'A', status: 'IN STOCK' },
    { name: 'B', status: 'OUT OF STOCK' }
  ]);
});

test('loadOverview populates overview pane', async () => {
  const mod = await loadModule();
  const col = makeEl();
  col.dataset.runId = '5';
  col.dataset.runUrl = 'http://run';
  const pane = makeEl();
  pane.id = 'overview-0';
  col.querySelector = sel => sel === '#overview-0' ? pane : null;

  mod.fetchScraperDecisions = async () => [{ name:'X', status:'IN STOCK' }];
  mod.appendSummary = (p, decisions) => { p.summary = decisions; };

  mod.fetchAPI = async () => ({
    html_url: 'http://gh',
    status: 'queued',
    conclusion: 'success',
    started_at: '2023-01-01T00:00:00Z',
    completed_at: '2023-01-01T01:00:00Z'
  });

  await mod.loadOverview(col, 0);
  assert.ok(pane.innerHTML.includes('View on GitHub'));
  assert.equal(col.dataset.overviewLoaded, 'true');
  assert.deepEqual(pane.summary, [{ name:'X', status:'IN STOCK' }]);
  assert.ok(pane.classList.classes.includes('fade-in-content'));
});

test('loadLogs filters log lines on search', async () => {
  const mod = await loadModule();
  const col = makeEl();
  col.dataset.runId = '9';
  const pane = makeEl();
  pane.id = 'logs-1';
  pane.dataset = {};
  const input = makeEl();
  input.type = 'text';
  const pre = makeEl();
  pane.querySelector = sel => {
    if (sel.startsWith('input')) return input;
    if (sel === 'pre') return pre;
    return null;
  };
  pane.children.push(input, pre);
  col.querySelector = sel => sel === '#logs-1' ? pane : null;

  global.localStorage = { getItem: () => 'tok' };
  const logText = 'LineA\nLineB';
  global.fetch = async () => ({ ok: true, blob: async () => 'blob' });
  global.JSZip = { loadAsync: async () => ({ files: { 'run.log': { async: async () => logText } } }) };

  await mod.loadLogs(col, 1);
  assert.equal(pane.dataset.loaded, 'true');
  input.value = 'b';
  const cb = input.getEvent('input');
  if (cb) cb();
  assert.equal(pre.textContent.toLowerCase().trim(), 'lineb');
});

test('loadArtifacts renders carousel when images found', async () => {
  const mod = await loadModule();
  const col = makeEl();
  col.dataset.runId = '3';
  const pane = makeEl();
  pane.id = 'artifacts-2';
  pane.dataset = {};
  col.querySelector = sel => sel === '#artifacts-2' ? pane : null;

  mod.fetchAPI = async () => ({ artifacts: [{ id: 1 }] });
  global.localStorage = { getItem: () => 'tok' };
  global.fetch = async () => ({ ok: true, blob: async () => 'blob' });
  global.JSZip = {
    loadAsync: async () => ({ files: { 'a.png': { async: async () => 'data' } } })
  };

  await mod.loadArtifacts(col, 2);
  assert.ok(pane.innerHTML.includes('carousel'));
  assert.equal(pane.dataset.loaded, 'true');
});

test('fetchRuns populates accordion and attaches handlers', async () => {
  const mod = await loadModule();
  const acc = makeEl();
  acc.id = 'runsAccordion';
  global.document = { getElementById: () => acc, createElement: () => makeEl() };

  mod.fetchAPI = async () => ({ runs: [{ id: 1, url: 'u', created_at: 'd' }] });
  mod.createAccordionItem = () => '<div class="accordion-collapse" id="c1"></div>';
  const colObj = { id: 'collapse1', addEventListener(ev, cb){ this.event = cb; }, querySelector(){return null;} };
  acc.querySelectorAll = () => [colObj];

  await mod.fetchRuns();
  assert.equal(acc.children.length, 1);
  assert.ok(colObj.event);
});
