import test from 'node:test';
import assert from 'assert';
import { escapeHTML, formatRunDate, cleanLogText, sanitizeUrl } from '../components/utils/utils.js';

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
