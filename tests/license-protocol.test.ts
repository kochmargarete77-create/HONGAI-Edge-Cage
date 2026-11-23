import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  decryptArtifact,
  encryptArtifact,
  generateInstallIdentity,
  generateSigningKeyPair,
  unwrapContentKey,
  wrapContentKeyForInstall
} from '../src/license-protocol.js';

test('wraps a release content key to one installation and rejects tampering', () => {
  const install = generateInstallIdentity();
  const signing = generateSigningKeyPair();
  const contentKey = randomBytes(32);
  const envelope = wrapContentKeyForInstall({
    contentKey,
    artifactId: 'edge-cage-0.2.0-windows-x64',
    installId: install.installId,
    clientPublicKeyPem: install.publicKeyPem,
    signingPrivateKeyPem: signing.privateKeyPem,
    ttlSeconds: 300
  });
  const unwrapped = unwrapContentKey({
    envelope,
    expectedArtifactId: 'edge-cage-0.2.0-windows-x64',
    expectedInstallId: install.installId,
    clientPrivateKeyPem: install.privateKeyPem,
    signingPublicKeyPem: signing.publicKeyPem
  });
  assert.deepEqual(unwrapped, contentKey);

  const tampered = { ...envelope, artifactId: 'other-artifact' };
  assert.throws(() => unwrapContentKey({
    envelope: tampered,
    expectedArtifactId: 'other-artifact',
    expectedInstallId: install.installId,
    clientPrivateKeyPem: install.privateKeyPem,
    signingPublicKeyPem: signing.publicKeyPem
  }));
});

test('encrypts release payloads with authenticated encryption', () => {
  const key = randomBytes(32);
  const plaintext = Buffer.from('HONG AI Edge Cage encrypted release payload');
  const encrypted = encryptArtifact(plaintext, key);
  assert.deepEqual(decryptArtifact(encrypted, key), plaintext);
  const tampered = Buffer.from(encrypted);
  const lastIndex = tampered.length - 1;
  tampered[lastIndex] = (tampered[lastIndex] ?? 0) ^ 1;
  assert.throws(() => decryptArtifact(tampered, key));
});
