import test from 'node:test';
import assert from 'assert';
import { escapeHTML, formatRunDate, cleanLogText, sanitizeUrl, extractCheckStockLog, getStatusBadge, normalizeEmail } from '../components/utils/utils.js';

global.window = { location: { origin: 'http://example.com' } };

test('escapeHTML escapes characters', () => {
  const result = escapeHTML('<div>"A&B\'</div>');
  assert.equal(result, '&lt;div&gt;&quot;A&amp;B&#39;&lt;/div&gt;');
});

test('formatRunDate formats ISO strings', () => {
  const result = formatRunDate('2023-01-02T15:04:00Z');
  assert.equal(result, '02-Jan-23, 03:04 PM');
});

test('cleanLogText removes debug prefixes', () => {
  const log = '2024-01-01T00:00:00Z hello\n##[debug]2024-01-01T00:00:01Z debug info';
  assert.equal(cleanLogText(log), 'hello\ndebug info');
});

test('sanitizeUrl filters unsafe protocols', () => {
  assert.equal(sanitizeUrl('javascript:alert(1)'), '');
  assert.equal(sanitizeUrl('/path'), 'http://example.com/path');
});

test('extractCheckStockLog trims relevant section', () => {
  const log = 'start\nLaunching browser\nwork\nRun actions/upload-artifact@v4\nend';
  assert.equal(extractCheckStockLog(log), 'Launching browser\nwork\n');
});

test('getStatusBadge renders badge html', () => {
  const html = getStatusBadge('queued', '');
  assert(html.includes('loader-2'));
  assert(html.includes('queued'.charAt(0).toUpperCase() + 'queued'.slice(1))); // 'Queued'
});

test('normalizeEmail lowercases and trims addresses', () => {
  assert.equal(normalizeEmail(' User@Example.Com '), 'user@example.com');
  assert.equal(normalizeEmail(null), '');
});
