import assert from 'node:assert/strict';
import test from 'node:test';
import { validateSourceArchiveEntries } from '../src/deployment.js';

const validListing = [
  'package/',
  'package/HONGAI-DELIVERY.json',
  'package/package.json',
  'package/platform/windows/Install-HONGAI-Edge-Cage.ps1'
].join('\n');

test('accepts a rooted HONG AI source delivery archive', () => {
  assert.equal(validateSourceArchiveEntries(validListing).length, 4);
});

test('rejects archive path traversal and alternate path syntax', () => {
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage/../escape.txt`));
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\nC:/escape.txt`));
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage\\escape.txt`));
  assert.throws(() => validateSourceArchiveEntries('package/package.json'));
});
