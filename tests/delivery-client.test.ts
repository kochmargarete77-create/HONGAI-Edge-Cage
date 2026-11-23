import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  assertApprovedReleaseUrl,
  retrieveArtifact,
  retryPendingReceipt
} from '../src/delivery-client.js';
import {
  encryptArtifact,
  generateSigningKeyPair,
  hashArtifactManifest,
  sha256,
  signArtifactManifest,
  wrapContentKeyForInstall
} from '../src/license-protocol.js';

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

test('failed finalization removes the decrypted archive and records failure', async () => {
  const tempBase = resolve(process.cwd(), '.test-tmp');
  await mkdir(tempBase, { recursive: true });
  const root = await mkdtemp(resolve(tempBase, 'delivery-cleanup-'));
  const outputPath = resolve(root, 'bundle.tgz');
  const signing = generateSigningKeyPair();
  const contentKey = randomBytes(32);
  const plaintext = Buffer.from('verified customer delivery payload');
  const encrypted = encryptArtifact(plaintext, contentKey);
  const downloadUrl = 'https://github.com/kochmargarete77-create/HONGAI-Edge-Cage/releases/download/test/bundle.enc';
  const manifest = {
    version: 1 as const,
    artifactId: 'delivery-cleanup-test',
    downloadUrl,
    ciphertextSha256: sha256(encrypted),
    plaintextSha256: sha256(plaintext)
  };
  const receiptStatuses: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.endsWith('/v1/activate')) {
      const request = JSON.parse(String(init?.body)) as {
        installId: string;
        clientPublicKeyPem: string;
      };
      const manifestHash = hashArtifactManifest(manifest);
      return Response.json({
        ok: true,
        activationId: 'activation-cleanup-test',
        receiptToken: 'receipt-cleanup-test',
        artifact: {
          id: manifest.artifactId,
          downloadUrl,
          ciphertextSha256: manifest.ciphertextSha256,
          plaintextSha256: manifest.plaintextSha256,
          manifestSignature: signArtifactManifest(manifest, signing.privateKeyPem)
        },
        envelope: wrapContentKeyForInstall({
          contentKey,
          artifactId: manifest.artifactId,
          artifactManifestSha256: manifestHash,
          installId: request.installId,
          clientPublicKeyPem: request.clientPublicKeyPem,
          signingPrivateKeyPem: signing.privateKeyPem
        })
      });
    }
    if (url === downloadUrl) {
      const response = new Response(Uint8Array.from(encrypted), {
        status: 200,
        headers: { 'Content-Type': 'application/octet-stream' }
      });
      Object.defineProperty(response, 'url', { value: downloadUrl });
      return response;
    }
    if (url.endsWith('/v1/receipt')) {
      const request = JSON.parse(String(init?.body)) as { status: string };
      receiptStatuses.push(request.status);
      return Response.json({ ok: true });
    }
    throw new Error(`Unexpected test URL: ${url}`);
  }) as typeof fetch;
  try {
    await assert.rejects(retrieveArtifact({
      serviceUrl: 'http://127.0.0.1:8787/',
      artifactId: manifest.artifactId,
      licenseKey: 'test-license',
      oneTimeToken: 'test-token',
      signingPublicKeyPem: signing.publicKeyPem,
      outputPath,
      finalize: async () => { throw new Error('forced finalize failure'); }
    }), /forced finalize failure/);
    await assert.rejects(stat(outputPath), (error: NodeJS.ErrnoException) => error.code === 'ENOENT');
    assert.deepEqual(receiptStatuses, ['FAILED']);
  } finally {
    globalThis.fetch = originalFetch;
    contentKey.fill(0);
    plaintext.fill(0);
    await rm(root, { recursive: true, force: true });
  }
});

test('failed receipt delivery creates an encrypted retryable outbox record', async () => {
  const tempBase = resolve(process.cwd(), '.test-tmp');
  await mkdir(tempBase, { recursive: true });
  const root = await mkdtemp(resolve(tempBase, 'receipt-retry-'));
  const outputPath = resolve(root, 'bundle.tgz');
  const licenseKey = 'test-license-outbox-protection';
  const receiptToken = 'receipt-retry-test-secret';
  const activationId = '../../escape:invalid\\activation-retry-test';
  const expectedPendingPath = `${outputPath}.receipt-${sha256(Buffer.from(activationId)).slice(0, 32)}.pending.json`;
  const signing = generateSigningKeyPair();
  const contentKey = randomBytes(32);
  const plaintext = Buffer.from('verified delivery payload with retryable receipt');
  const encrypted = encryptArtifact(plaintext, contentKey);
  const downloadUrl = 'https://github.com/kochmargarete77-create/HONGAI-Edge-Cage/releases/download/test/retry.enc';
  const manifest = {
    version: 1 as const,
    artifactId: 'delivery-retry-test',
    downloadUrl,
    ciphertextSha256: sha256(encrypted),
    plaintextSha256: sha256(plaintext)
  };
  const originalFetch = globalThis.fetch;
  let rejectReceipt = true;
  let receiptAttempts = 0;
  let submittedStatus = '';
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.endsWith('/v1/activate')) {
      const request = JSON.parse(String(init?.body)) as {
        installId: string;
        clientPublicKeyPem: string;
      };
      const manifestHash = hashArtifactManifest(manifest);
      return Response.json({
        ok: true,
        activationId,
        receiptToken,
        artifact: {
          id: manifest.artifactId,
          downloadUrl,
          ciphertextSha256: manifest.ciphertextSha256,
          plaintextSha256: manifest.plaintextSha256,
          manifestSignature: signArtifactManifest(manifest, signing.privateKeyPem)
        },
        envelope: wrapContentKeyForInstall({
          contentKey,
          artifactId: manifest.artifactId,
          artifactManifestSha256: manifestHash,
          installId: request.installId,
          clientPublicKeyPem: request.clientPublicKeyPem,
          signingPrivateKeyPem: signing.privateKeyPem
        })
      });
    }
    if (url === downloadUrl) {
      const response = new Response(Uint8Array.from(encrypted), {
        status: 200,
        headers: { 'Content-Type': 'application/octet-stream' }
      });
      Object.defineProperty(response, 'url', { value: downloadUrl });
      return response;
    }
    if (url.endsWith('/v1/receipt')) {
      receiptAttempts += 1;
      submittedStatus = (JSON.parse(String(init?.body)) as { status: string }).status;
      if (rejectReceipt) throw new Error('simulated receipt outage');
      return Response.json({ ok: true });
    }
    throw new Error(`Unexpected test URL: ${url}`);
  }) as typeof fetch;
  try {
    await writeFile(expectedPendingPath, 'intentional collision\n', { flag: 'wx' });
    await assert.rejects(retrieveArtifact({
      serviceUrl: 'http://127.0.0.1:8787/',
      artifactId: manifest.artifactId,
      licenseKey,
      oneTimeToken: 'test-token',
      signingPublicKeyPem: signing.publicKeyPem,
      outputPath,
      finalize: async () => {}
    }), /INSTALLED completed, but its receipt could not be recorded or persisted/);
    await stat(outputPath);
    assert.equal(submittedStatus, 'INSTALLED');
    assert.equal(receiptAttempts, 3);
    await rm(outputPath, { force: true });
    await rm(expectedPendingPath, { force: true });

    const result = await retrieveArtifact({
      serviceUrl: 'http://127.0.0.1:8787/',
      artifactId: manifest.artifactId,
      licenseKey,
      oneTimeToken: 'test-token',
      signingPublicKeyPem: signing.publicKeyPem,
      outputPath,
      finalize: async () => {}
    });
    assert.equal(result.receiptRecorded, false);
    assert.equal(result.deliveryState, 'PENDING_RECEIPT');
    assert.equal(result.status, 'INSTALLED');
    assert.ok(result.receiptPendingPath);
    const pendingPath = result.receiptPendingPath;
    assert.equal(pendingPath.startsWith(`${outputPath}.receipt-`), true);
    const serialized = await readFile(pendingPath, 'utf8');
    assert.equal(serialized.includes(receiptToken), false);
    assert.equal(serialized.includes(activationId), false);
    await assert.rejects(retryPendingReceipt(pendingPath, 'wrong-license-key'));
    await stat(pendingPath);

    rejectReceipt = false;
    await retryPendingReceipt(pendingPath, licenseKey);
    assert.equal(submittedStatus, 'INSTALLED');
    assert.equal(receiptAttempts, 7);
    await assert.rejects(stat(pendingPath), (error: NodeJS.ErrnoException) => error.code === 'ENOENT');
  } finally {
    globalThis.fetch = originalFetch;
    contentKey.fill(0);
    plaintext.fill(0);
    await rm(root, { recursive: true, force: true });
  }
});
