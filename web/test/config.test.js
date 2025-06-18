import test from 'node:test';
import assert from 'assert';
import * as config from '../components/config/config.js';

test('API endpoint constants are defined', () => {
  assert.equal(config.API_STATUS, '/api/status');
  assert.equal(config.API_RUNS, '/api/runs');
  assert.equal(config.API_RUN, '/api/run');
  assert.equal(config.API_LOGS, '/api/logs');
  assert.equal(config.API_ARTIFACT, '/api/artifact');
  assert.equal(config.API_LOGIN, '/api/login');
  assert.equal(config.API_USER_LOGIN, '/api/user-login');
});
