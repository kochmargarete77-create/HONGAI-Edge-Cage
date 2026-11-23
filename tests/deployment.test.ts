import assert from 'node:assert/strict';
import test from 'node:test';
import {
  validateSourceArchiveEntries,
  validateTarEntryTypes,
  validateTarExpandedSize
} from '../src/deployment.js';

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
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage/file:stream`));
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage/CON.txt`));
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage/trailing.`));
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage/PACKAGE.JSON`));
  assert.throws(() => validateSourceArchiveEntries(`${validListing}\npackage/cafe\u0301.txt`));
  assert.throws(() => validateSourceArchiveEntries('package/package.json'));
});

test('allows only regular files and directories in tar metadata', () => {
  assert.doesNotThrow(() => validateTarEntryTypes(
    '-rw-r--r-- 0/0 10 2026-11-22 package/package.json\n' +
    'drwxr-xr-x 0/0 0 2026-11-22 package/docs/'
  ));
  assert.throws(() => validateTarEntryTypes(
    'lrwxrwxrwx 0/0 0 2026-11-22 package/link -> ../../escape'
  ));
  assert.throws(() => validateTarEntryTypes(
    'prw-r--r-- 0/0 0 2026-11-22 package/pipe'
  ));
});

test('limits the total expanded archive size for GNU and BSD tar listings', () => {
  assert.equal(validateTarExpandedSize(
    '-rw-r--r-- 0/0 10 2026-11-22 package/package.json\n' +
    'drwxr-xr-x 0/0 0 2026-11-22 package/docs/'
  ), 10);
  assert.equal(validateTarExpandedSize(
    '-rw-r--r--  0 0 25 Nov 22 06:17 package/package.json\n' +
    'drwxr-xr-x  0 0 0 Nov 22 06:17 package/docs/'
  ), 25);
  assert.throws(() => validateTarExpandedSize(
    '-rw-r--r-- 0/0 101 2026-11-22 package/package.json',
    100
  ));
});
