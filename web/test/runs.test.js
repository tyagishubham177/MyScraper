import test from 'node:test';
import assert from 'assert';
import {
  parseScraperDecisionsFromLog,
  createSkeleton,
  createAccordionItem,
  appendSummary,
  fetchScraperDecisions,
  loadOverview,
  loadLogs,
  loadArtifacts,
  fetchRuns
} from '../components/runs/runs.js';
import { formatRunDate, getStatusBadge } from '../components/utils/utils.js';

test('parseScraperDecisionsFromLog extracts product statuses', () => {
  const log = `✅ Product 'A' (URL: http://a) is IN STOCK.\n` +
              `❌ Product 'B' (URL: http://b) is OUT OF STOCK.\n` +
              `Something else`;
  const result = parseScraperDecisionsFromLog(log);
  assert.deepEqual(result, [
    { name: 'A', status: 'IN STOCK' },
    { name: 'B', status: 'OUT OF STOCK' }
  ]);
});

test('createSkeleton returns requested number of items', () => {
  const html = createSkeleton(2);
  const matches = html.match(/accordion-item/g) || [];
  assert.equal(matches.length, 2);
});

test('createAccordionItem builds markup with run info', () => {
  const run = {
    id: 1,
    url: 'http://example.com',
    created_at: '2024-01-02T15:04:00Z',
    conclusion: 'success'
  };
  const html = createAccordionItem(run, 0);
  assert(html.includes('id="heading0"'));
  assert(html.includes('id="collapse0"'));
  assert(html.includes(formatRunDate(run.created_at)));
  assert(html.includes(getStatusBadge(run.status, run.conclusion)));
});

test('parseScraperDecisionsFromLog handles empty and irrelevant logs', () => {
  assert.deepEqual(parseScraperDecisionsFromLog(''), []);
  const log = 'Some log line\nAnother line';
  assert.deepEqual(parseScraperDecisionsFromLog(log), []);
});

function makeEl() {
  let html = '';
  return {
    dataset: {},
    get innerHTML() { return html; },
    set innerHTML(v) { html = v; }
  };
}

test('appendSummary renders product summary and triggers icon replace', () => {
  const pane = makeEl();
  let replaced = false;
  global.lucide = { replace: () => { replaced = true; } };
  global.setTimeout = (fn) => { fn(); };
  const decisions = [
    { name: 'A', status: 'IN STOCK' },
    { name: 'B', status: 'OUT OF STOCK' },
    { name: 'C', status: 'UNKNOWN' }
  ];
  appendSummary(pane, decisions);
  assert.ok(pane.innerHTML.includes('Product Stock Summary'));
  assert.ok(pane.innerHTML.includes('A:'));
  assert.equal(pane.dataset.productSummaryLoaded, 'true');
  assert.equal(replaced, true);
});

test('appendSummary handles empty decisions', () => {
  const pane = makeEl();
  let replaced = false;
  global.lucide = { replace: () => { replaced = true; } };
  global.setTimeout = (fn) => { fn(); };
  appendSummary(pane, []);
  assert.ok(pane.innerHTML.includes('No product stock decisions'));
  assert.equal(pane.dataset.productSummaryLoaded, 'true');
  assert.equal(replaced, false);
});

function makePane() {
  const pane = {
    dataset: {},
    classList: { classes: [], add(c){ this.classes.push(c); } },
    events: {},
    addEventListener(ev, cb){ this.events[ev] = cb; },
    getEvent(ev){ return this.events[ev]; }
  };
  let html = '';
  Object.defineProperty(pane, 'innerHTML', {
    get(){ return html; },
    set(v){ html = v; }
  });
  pane.querySelector = sel => pane[sel];
  return pane;
}

function makeCol(runId, runUrl, paneKey, pane) {
  return {
    id: 'collapse' + runId,
    dataset: { runId: String(runId), runUrl },
    events:{},
    addEventListener(ev, cb){ this.events[ev] = cb; },
    getEvent(ev){ return this.events[ev]; },
    querySelector(sel){
      if(sel === `#${paneKey}-${runId}`) return pane;
      if(sel === `#logs-tab-${runId}`) return { addEventListener:(ev,cb,opts)=>{ this.logEvt=cb; }, getEvent:()=>this.logEvt };
      if(sel === `#artifacts-tab-${runId}`) return { addEventListener:(ev,cb,opts)=>{ this.artEvt=cb; }, getEvent:()=>this.artEvt };
      return null;
    },
    querySelectorAll(){ return []; }
  };
}

function stubFetch(responses) {
  global.fetch = async (url, opts) => {
    for (const [prefix, resp] of responses) {
      if (url.startsWith(prefix)) return typeof resp === 'function' ? resp() : resp;
    }
    return { ok:false, status:404, json:async()=>({}) };
  };
}

test('fetchScraperDecisions chooses correct log file', async () => {
  global.localStorage = { getItem: () => 'tok' };
  stubFetch([
    ['/api/logs', { ok: true, blob: async () => 'blob1' }]
  ]);
  global.JSZip = {
    async loadAsync(blob){
      assert.equal(blob, 'blob1');
      return { files: { 'runStockChecker.log': { async: async () => "✅ Product 'A' (URL: http://a) is IN STOCK." } } };
    }
  };
  const res = await fetchScraperDecisions('1');
  assert.deepEqual(res, [{ name: 'A', status: 'IN STOCK' }]);
});

test('fetchScraperDecisions falls back to alternative names', async () => {
  global.localStorage = { getItem: () => 'tok' };
  stubFetch([
    ['/api/logs', { ok: true, blob: async () => 'blob2' }]
  ]);
  global.JSZip = {
    async loadAsync(){
      return { files: { 'run_stock_checker.log': { async: async () => "✅ Product 'B' (URL: http://b) is IN STOCK." } } };
    }
  };
  const res = await fetchScraperDecisions('2');
  assert.deepEqual(res, [{ name: 'B', status: 'IN STOCK' }]);
});

test('loadOverview populates info and summary', async () => {
  const pane = makePane();
  const col = makeCol(3, 'http://run', 'overview', pane);
  global.localStorage = { getItem: () => 'tok' };
  stubFetch([
    ['/api/run', { ok: true, json: async () => ({ html_url:'http://gh', status:'done', conclusion:'success', started_at:'2024-01-01T00:00:00Z', completed_at:'2024-01-01T01:00:00Z' }) }],
    ['/api/logs', { ok: true, blob: async () => 'blob3' }]
  ]);
  global.JSZip = {
    async loadAsync(){
      return { files: { 'runstockchecker.log': { async: async () => "✅ Product 'C' (URL: http://c) is IN STOCK." } } };
    }
  };
  await loadOverview(col, 3);
  assert.ok(pane.innerHTML.includes('View on GitHub'));
  assert.equal(col.dataset.overviewLoaded, 'true');
  assert.equal(pane.dataset.productSummaryLoaded, 'true');
});

test('loadLogs fetches and filters log text', async () => {
  const logsPane = makePane();
  logsPane.pre = { textContent: '' };
  logsPane.input = { value: '', addEventListener(ev, cb){ this.cb = cb; } };
  logsPane.querySelector = sel => sel==='pre' ? logsPane.pre : logsPane.input;
  const col = { dataset:{ runId:'4' }, querySelector: () => logsPane };
  global.localStorage = { getItem: () => 'tok' };
  stubFetch([
    ['/api/logs', { ok: true, blob: async () => 'blob4' }]
  ]);
  global.JSZip = { async loadAsync(){ return { files:{ 'runstockchecker.log': { async: async () => 'one\ntwo match' } } }; } };
  await loadLogs(col, 4);
  assert.equal(logsPane.dataset.loaded, 'true');
  assert.ok(logsPane.pre.textContent.includes('one'));
  logsPane.input.value = 'match';
  logsPane.input.cb();
  assert.equal(logsPane.pre.textContent.trim(), 'two match');
});

test('loadArtifacts builds carousel and counter', async () => {
  const counter = { textContent:'' };
  const carouselEl = {
    items:[{ active:true }],
    querySelectorAll: sel => carouselEl.items,
    querySelector: sel => sel === '.carousel-item.active' ? carouselEl.items[0] : counter,
    addEventListener(){ }
  };
  const pane = makePane();
  pane.querySelector = sel => carouselEl;
  const col = makeCol(5, 'u', 'artifacts', pane);
  global.localStorage = { getItem: () => 'tok' };
  stubFetch([
    ['/api/run', { ok: true, json: async () => ({ artifacts:[{ id:1 }] }) }],
    ['/api/artifact', { ok: true, blob: async () => 'blob5' }]
  ]);
  global.JSZip = { async loadAsync(){ return { files:{ 'img.png': { async: async () => 'zzz' } } }; } };
  await loadArtifacts(col, 5);
  assert.equal(pane.dataset.loaded, 'true');
  assert.ok(pane.innerHTML.includes('carousel'));
  assert.equal(counter.textContent, '1/1');
});

test('fetchRuns populates accordion and hooks events', async () => {
  const acc = {
    innerHTML:'',
    children:[],
    appendChild(el){ this.children.push(el); },
    querySelectorAll: () => [col]
  };
  const pane = makePane();
  const col = makeCol(6, 'http://r', 'overview', pane);
  global.document = {
    getElementById: () => acc,
    createElement: () => ({ className:'', innerHTML:'', appendChild(){}, querySelectorAll: () => [], querySelector: () => null })
  };
  global.localStorage = { getItem: () => 'tok' };
  stubFetch([
    ['/api/runs', { ok: true, json: async () => ({ runs:[{ id:6, url:'u', created_at:'2024-01-01T00:00:00Z', conclusion:'success' }] }) }],
    ['/api/run', { ok: true, json: async () => ({ html_url:'x', status:'done', conclusion:'success', started_at:'2024-01-01T00:00:00Z', completed_at:'2024-01-01T01:00:00Z', artifacts:[] }) }]
  ]);
  global.JSZip = { async loadAsync(){ return { files:{ } }; } };
  await fetchRuns();
  assert.equal(acc.children.length, 1);
  await col.getEvent('show.bs.collapse')();
  assert.equal(pane.dataset.productSummaryLoaded, 'true');
});
