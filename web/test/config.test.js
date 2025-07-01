import test from 'node:test';
import assert from 'assert';
import * as config from '../components/config/config.js';

test('API endpoint constants are defined', () => {
  assert.equal(config.API_STATUS, '/api/github?action=status');
  assert.equal(config.API_RUNS, '/api/github?action=runs');
  assert.equal(config.API_RUN, '/api/github?action=run');
  assert.equal(config.API_LOGS, '/api/github?action=logs');
  assert.equal(config.API_ARTIFACT, '/api/github?action=artifact');
  assert.equal(config.API_LOGIN, '/api/login');
  assert.equal(config.API_USER_LOGIN, '/api/login');
});
