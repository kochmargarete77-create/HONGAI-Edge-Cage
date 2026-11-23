import assert from 'node:assert/strict';
import test from 'node:test';
import { publicLicenseServiceError } from '../services/license-service/http-errors.js';

test('license service exposes only whitelisted client errors as 4xx', () => {
  assert.deepEqual(publicLicenseServiceError(new Error('LICENSE_DENIED')), {
    status: 403,
    code: 'LICENSE_DENIED'
  });
  assert.deepEqual(publicLicenseServiceError(new Error('Invalid artifactId.')), {
    status: 400,
    code: 'INVALID_REQUEST'
  });
  assert.deepEqual(publicLicenseServiceError(new SyntaxError('bad JSON')), {
    status: 400,
    code: 'INVALID_REQUEST'
  });
  assert.deepEqual(publicLicenseServiceError(new Error('Request body is too large.')), {
    status: 413,
    code: 'REQUEST_TOO_LARGE'
  });
});

test('license service maps storage and other internal failures to a retryable 500', () => {
  for (const error of [
    new Error('LICENSE_DATABASE_LOCK_TIMEOUT'),
    new Error('LICENSE_DATABASE_AUDIT_CHAIN_INVALID'),
    new Error('database write failed'),
    'non-error rejection'
  ]) {
    assert.deepEqual(publicLicenseServiceError(error), {
      status: 500,
      code: 'INTERNAL_ERROR'
    });
  }
});
