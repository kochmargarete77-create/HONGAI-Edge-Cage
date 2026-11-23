import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  appendDatabaseEvent,
  emptyDatabase,
  mutateDatabase,
  verifyDatabaseEvents,
  withDatabaseLock,
  writeDatabase,
  type LicenseDatabase
} from '../services/license-service/storage.js';

const testRoot = resolve(process.cwd(), '.test-tmp');

test('cross-process database lock serializes concurrent mutations', async () => {
  await mkdir(testRoot, { recursive: true });
  const dataRoot = await mkdtemp(resolve(testRoot, 'storage-lock-'));
  try {
    await writeDatabase(dataRoot, emptyDatabase());
    await Promise.all(Array.from({ length: 12 }, (_, index) =>
      mutateDatabase(dataRoot, async (database) => {
        await new Promise((resolveWait) => setTimeout(resolveWait, 5));
        appendDatabaseEvent(database, 'CONCURRENT_TEST', 'test', { index });
      })
    ));
    const database = JSON.parse(
      await readFile(resolve(dataRoot, 'database.json'), 'utf8')
    ) as LicenseDatabase;
    assert.equal(database.events.length, 12);
    assert.equal(verifyDatabaseEvents(database.events), true);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test('an abandoned empty lock directory can be reclaimed after the stale threshold', async () => {
  await mkdir(testRoot, { recursive: true });
  const dataRoot = await mkdtemp(resolve(testRoot, 'storage-stale-lock-'));
  try {
    await mkdir(resolve(dataRoot, 'database.lock'));
    await new Promise((resolveWait) => setTimeout(resolveWait, 5));
    let entered = false;
    await withDatabaseLock(dataRoot, () => {
      entered = true;
    }, { staleAfterMs: 1, timeoutMs: 1_000 });
    assert.equal(entered, true);
  } finally {
    await rm(dataRoot, { recursive: true, force: true });
  }
});
