import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  decryptArtifact,
  encryptArtifact,
  generateInstallIdentity,
  generateSigningKeyPair,
  hashArtifactManifest,
  signArtifactManifest,
  unwrapContentKey,
  verifyArtifactManifestSignature,
  wrapContentKeyForInstall
} from '../src/license-protocol.js';

test('signs immutable artifact identity and rejects descriptor substitution', () => {
  const signing = generateSigningKeyPair();
  const manifest = {
    version: 1 as const,
    artifactId: 'edge-cage-0.2.0-windows-x64',
    downloadUrl: 'https://github.com/example/project/releases/download/v1/bundle.enc',
    ciphertextSha256: '1'.repeat(64),
    plaintextSha256: '2'.repeat(64)
  };
  const signature = signArtifactManifest(manifest, signing.privateKeyPem);
  assert.equal(verifyArtifactManifestSignature(manifest, signature, signing.publicKeyPem), true);
  assert.equal(hashArtifactManifest(manifest).length, 64);
  assert.equal(verifyArtifactManifestSignature(
    { ...manifest, downloadUrl: `${manifest.downloadUrl}.substituted` },
    signature,
    signing.publicKeyPem
  ), false);
});

test('wraps a release content key to one installation and rejects tampering', () => {
  const install = generateInstallIdentity();
  const signing = generateSigningKeyPair();
  const contentKey = randomBytes(32);
  const artifactManifestSha256 = 'a'.repeat(64);
  const envelope = wrapContentKeyForInstall({
    contentKey,
    artifactId: 'edge-cage-0.2.0-windows-x64',
    artifactManifestSha256,
    installId: install.installId,
    clientPublicKeyPem: install.publicKeyPem,
    signingPrivateKeyPem: signing.privateKeyPem,
    ttlSeconds: 300
  });
  const unwrapped = unwrapContentKey({
    envelope,
    expectedArtifactId: 'edge-cage-0.2.0-windows-x64',
    expectedArtifactManifestSha256: artifactManifestSha256,
    expectedInstallId: install.installId,
    clientPrivateKeyPem: install.privateKeyPem,
    signingPublicKeyPem: signing.publicKeyPem
  });
  assert.deepEqual(unwrapped, contentKey);

  const tampered = { ...envelope, artifactId: 'other-artifact' };
  assert.throws(() => unwrapContentKey({
    envelope: tampered,
    expectedArtifactId: 'other-artifact',
    expectedArtifactManifestSha256: artifactManifestSha256,
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
