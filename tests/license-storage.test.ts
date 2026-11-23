import assert from 'node:assert/strict';
import test from 'node:test';
import {
  appendDatabaseEvent,
  emptyDatabase,
  verifyDatabaseEvents
} from '../services/license-service/storage.js';

test('license-service audit events form a tamper-evident hash chain', () => {
  const database = emptyDatabase();
  appendDatabaseEvent(database, 'LICENSE_ISSUED', 'admin', { licenseId: 'license-a' });
  appendDatabaseEvent(database, 'CONTENT_KEY_ISSUED', 'client-hash', { artifactId: 'release-a' });
  assert.equal(verifyDatabaseEvents(database.events), true);

  database.events[0]!.details.licenseId = 'modified';
  assert.equal(verifyDatabaseEvents(database.events), false);
});
