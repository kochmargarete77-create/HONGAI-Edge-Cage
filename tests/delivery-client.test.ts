import assert from 'node:assert/strict';
import test from 'node:test';
import { assertApprovedReleaseUrl } from '../src/delivery-client.js';

test('delivery client accepts only HTTPS GitHub release hosts', () => {
  assert.equal(
    assertApprovedReleaseUrl('https://github.com/example/project/releases/download/v1/bundle.enc').hostname,
    'github.com'
  );
  assert.equal(
    assertApprovedReleaseUrl('https://release-assets.githubusercontent.com/github-production-release-asset/file').hostname,
    'release-assets.githubusercontent.com'
  );
  assert.throws(() => assertApprovedReleaseUrl('http://github.com/example/project/bundle.enc'));
  assert.throws(() => assertApprovedReleaseUrl('https://example.com/bundle.enc'));
});
