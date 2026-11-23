import assert from 'node:assert/strict';
import test from 'node:test';
import { redactSensitive, verifyAuditChain, type AuditEvent } from '../src/audit.js';

test('redacts credentials recursively before audit persistence', () => {
  assert.deepEqual(redactSensitive({
    licenseKey: 'secret-license',
    nested: { oneTimeToken: 'secret-token', result: 'ok' }
  }), {
    licenseKey: '[REDACTED]',
    nested: { oneTimeToken: '[REDACTED]', result: 'ok' }
  });
});

test('rejects a modified audit chain', () => {
  const fake = [{
    sequence: 1,
    id: 'event',
    timestamp: '2026-01-01T00:00:00.000Z',
    type: 'TEST',
    actor: 'controller',
    details: {},
    previousHash: 'GENESIS',
    hash: 'not-a-real-hash'
  }] as AuditEvent[];
  assert.equal(verifyAuditChain(fake), false);
});
