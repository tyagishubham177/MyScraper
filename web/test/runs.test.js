import test from 'node:test';
import assert from 'assert';
import { parseScraperDecisionsFromLog, createSkeleton, createAccordionItem, appendSummary } from '../components/runs/runs.js';
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
