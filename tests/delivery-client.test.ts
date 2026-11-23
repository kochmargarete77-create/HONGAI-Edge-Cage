import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  abandonActivation,
  assertApprovedDeliveryProxyUrl,
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

test('delivery proxy is restricted to an unauthenticated loopback listener', () => {
  assert.equal(assertApprovedDeliveryProxyUrl('http://127.0.0.1:7897').href, 'http://127.0.0.1:7897/');
  assert.equal(assertApprovedDeliveryProxyUrl('http://localhost:7890').port, '7890');
  assert.throws(() => assertApprovedDeliveryProxyUrl('http://192.168.1.2:7890'));
  assert.throws(() => assertApprovedDeliveryProxyUrl('http://127.0.0.1'));
  assert.throws(() => assertApprovedDeliveryProxyUrl('http://user:pass@127.0.0.1:7890'));
  assert.throws(() => assertApprovedDeliveryProxyUrl('http://127.0.0.1:7890/?redirect=evil'));
});

test('definite license refusal removes only a newly unbound recovery file', async () => {
  const tempBase = resolve(process.cwd(), '.test-tmp');
  await mkdir(tempBase, { recursive: true });
  const root = await mkdtemp(resolve(tempBase, 'license-refusal-'));
  const outputPath = resolve(root, 'bundle.tgz');
  const recoveryPath = `${outputPath}.activation.pending.json`;
  const signing = generateSigningKeyPair();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => Response.json(
    { ok: false, error: 'LICENSE_DENIED' },
    { status: 403 }
  )) as typeof fetch;
  try {
    await assert.rejects(retrieveArtifact({
      serviceUrl: 'http://127.0.0.1:8787/',
      artifactId: 'license-refusal-test',
      licenseKey: 'mistyped-license',
      oneTimeToken: 'unused-token',
      signingPublicKeyPem: signing.publicKeyPem,
      outputPath
    }), /LICENSE_DENIED/);
    await assert.rejects(stat(recoveryPath), (error: NodeJS.ErrnoException) => error.code === 'ENOENT');
  } finally {
    globalThis.fetch = originalFetch;
    await rm(root, { recursive: true, force: true });
  }
});

test('transient activation HTTP failures preserve the same recovery identity', async () => {
  const tempBase = resolve(process.cwd(), '.test-tmp');
  await mkdir(tempBase, { recursive: true });
  const root = await mkdtemp(resolve(tempBase, 'activation-http-recovery-'));
  const signing = generateSigningKeyPair();
  const originalFetch = globalThis.fetch;
  try {
    for (const status of [429, 500]) {
      const outputPath = resolve(root, `bundle-${status}.tgz`);
      const recoveryPath = `${outputPath}.activation.pending.json`;
      const installIds: string[] = [];
      globalThis.fetch = (async (_input, init) => {
        const request = JSON.parse(String(init?.body)) as { installId: string };
        installIds.push(request.installId);
        return Response.json(
          { ok: false, error: status === 429 ? 'RATE_LIMITED' : 'INTERNAL_ERROR' },
          { status }
        );
      }) as typeof fetch;

      const options = {
        serviceUrl: 'http://127.0.0.1:8787/',
        artifactId: `transient-http-${status}`,
        licenseKey: `test-license-${status}`,
        oneTimeToken: `test-token-${status}`,
        signingPublicKeyPem: signing.publicKeyPem,
        outputPath
      };
      await assert.rejects(retrieveArtifact(options), /RATE_LIMITED|INTERNAL_ERROR/);
      assert.equal((await stat(recoveryPath)).isFile(), true);
      await assert.rejects(retrieveArtifact(options), /RATE_LIMITED|INTERNAL_ERROR/);
      assert.equal(installIds.length, 2);
      assert.equal(installIds[0], installIds[1]);
    }
  } finally {
    globalThis.fetch = originalFetch;
    await rm(root, { recursive: true, force: true });
  }
});

test('failed finalization remains recoverable until an explicit FAILED abandonment', async () => {
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
  let rejectReceipts = true;
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
      if (rejectReceipts) throw new Error('simulated FAILED receipt outage');
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
    assert.equal((await stat(`${outputPath}.activation.pending.json`)).isFile(), true);
    assert.deepEqual(receiptStatuses, []);
    const abandoned = await abandonActivation({
      activationRecoveryPath: `${outputPath}.activation.pending.json`,
      artifactOutputPath: outputPath,
      licenseKey: 'test-license',
      expectedServiceUrl: 'http://127.0.0.1:8787/',
      expectedArtifactId: manifest.artifactId,
      signingPublicKeyPem: signing.publicKeyPem
    });
    assert.equal(abandoned.status, 'FAILED');
    assert.equal(abandoned.receiptRecorded, false);
    assert.ok(abandoned.receiptPendingPath);
    assert.equal((await readFile(abandoned.receiptPendingPath, 'utf8')).includes('receipt-cleanup-test'), false);
    assert.deepEqual(receiptStatuses, ['FAILED', 'FAILED', 'FAILED']);
    await assert.rejects(
      stat(`${outputPath}.activation.pending.json`),
      (error: NodeJS.ErrnoException) => error.code === 'ENOENT'
    );
    rejectReceipts = false;
    await retryPendingReceipt(abandoned.receiptPendingPath, 'test-license');
    assert.equal(receiptStatuses.at(-1), 'FAILED');
    await assert.rejects(
      stat(abandoned.receiptPendingPath),
      (error: NodeJS.ErrnoException) => error.code === 'ENOENT'
    );
  } finally {
    globalThis.fetch = originalFetch;
    contentKey.fill(0);
    plaintext.fill(0);
    await rm(root, { recursive: true, force: true });
  }
});

test('lost activation response resumes with the same bound identity and renewed envelope', async () => {
  const tempBase = resolve(process.cwd(), '.test-tmp');
  await mkdir(tempBase, { recursive: true });
  const root = await mkdtemp(resolve(tempBase, 'activation-resume-'));
  const outputPath = resolve(root, 'bundle.tgz');
  const recoveryPath = `${outputPath}.activation.pending.json`;
  const signing = generateSigningKeyPair();
  const contentKey = randomBytes(32);
  const plaintext = Buffer.from('resumable delivery payload');
  const encrypted = encryptArtifact(plaintext, contentKey);
  const downloadUrl = 'https://github.com/example/project/releases/download/test/resume.enc';
  const manifest = {
    version: 1 as const,
    artifactId: 'delivery-activation-resume-test',
    downloadUrl,
    ciphertextSha256: sha256(encrypted),
    plaintextSha256: sha256(plaintext)
  };
  const manifestSignature = signArtifactManifest(manifest, signing.privateKeyPem);
  const activationRequests: Array<{ installId: string; clientPublicKeyPem: string }> = [];
  let activationAttempts = 0;
  let resumeAttempts = 0;
  let downloadAttempts = 0;
  let receiptAttempts = 0;
  const originalFetch = globalThis.fetch;

  function activationResponse(request: { installId: string; clientPublicKeyPem: string }): Response {
    return Response.json({
      ok: true,
      activationId: 'activation-resume-test',
      receiptToken: 'HA-RCT-resume-test',
      recoveryToken: 'HA-REC-resume-test',
      artifact: {
        id: manifest.artifactId,
        downloadUrl,
        ciphertextSha256: manifest.ciphertextSha256,
        plaintextSha256: manifest.plaintextSha256,
        manifestSignature
      },
      envelope: wrapContentKeyForInstall({
        contentKey,
        artifactId: manifest.artifactId,
        artifactManifestSha256: hashArtifactManifest(manifest),
        installId: request.installId,
        clientPublicKeyPem: request.clientPublicKeyPem,
        signingPrivateKeyPem: signing.privateKeyPem,
        ttlSeconds: 300
      })
    });
  }

  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.endsWith('/v1/activate')) {
      const request = JSON.parse(String(init?.body)) as { installId: string; clientPublicKeyPem: string };
      activationRequests.push(request);
      activationAttempts += 1;
      if (activationAttempts === 1) {
        throw new Error('simulated response loss after activation commit');
      }
      return activationResponse(request);
    }
    if (url.endsWith('/v1/activation/resume')) {
      const request = JSON.parse(String(init?.body)) as { installId: string; clientPublicKeyPem: string };
      resumeAttempts += 1;
      return activationResponse(request);
    }
    if (url === downloadUrl) {
      downloadAttempts += 1;
      if (downloadAttempts === 1) {
        throw new Error('simulated interrupted artifact download');
      }
      const response = new Response(Uint8Array.from(encrypted), {
        status: 200,
        headers: { 'Content-Type': 'application/octet-stream' }
      });
      Object.defineProperty(response, 'url', { value: downloadUrl });
      return response;
    }
    if (url.endsWith('/v1/receipt')) {
      receiptAttempts += 1;
      return Response.json({ ok: true });
    }
    throw new Error(`Unexpected test URL: ${url}`);
  }) as typeof fetch;

  try {
    const options = {
      serviceUrl: 'http://127.0.0.1:8787/',
      artifactId: manifest.artifactId,
      licenseKey: 'test-license-activation-recovery',
      oneTimeToken: 'test-token-used-once',
      signingPublicKeyPem: signing.publicKeyPem,
      outputPath
    };
    await assert.rejects(retrieveArtifact(options), /simulated response loss/);
    const protectedState = await readFile(recoveryPath, 'utf8');
    assert.equal(protectedState.includes(activationRequests[0]!.installId), false);
    assert.equal(protectedState.includes('clientPrivateKeyPem'), false);
    await assert.rejects(stat(outputPath), (error: NodeJS.ErrnoException) => error.code === 'ENOENT');

    await assert.rejects(retrieveArtifact(options), /simulated interrupted artifact download/);
    const resumableState = await readFile(recoveryPath, 'utf8');
    assert.equal(resumableState.includes('HA-RCT-resume-test'), false);
    assert.equal(resumableState.includes('HA-REC-resume-test'), false);

    const result = await retrieveArtifact(options);
    assert.equal(result.status, 'DELIVERED');
    assert.equal(result.receiptRecorded, true);
    assert.equal(activationAttempts, 2);
    assert.equal(resumeAttempts, 2);
    assert.equal(downloadAttempts, 2);
    assert.equal(receiptAttempts, 1);
    assert.equal(activationRequests[0]!.installId, activationRequests[1]!.installId);
    assert.equal(activationRequests[0]!.clientPublicKeyPem, activationRequests[1]!.clientPublicKeyPem);
    await stat(outputPath);
    await assert.rejects(stat(recoveryPath), (error: NodeJS.ErrnoException) => error.code === 'ENOENT');
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
    }), /INSTALLED completed, but its encrypted receipt outbox could not be persisted/);
    await stat(outputPath);
    assert.equal(submittedStatus, '');
    assert.equal(receiptAttempts, 0);
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
    assert.equal(receiptAttempts, 4);
    await assert.rejects(stat(pendingPath), (error: NodeJS.ErrnoException) => error.code === 'ENOENT');
  } finally {
    globalThis.fetch = originalFetch;
    contentKey.fill(0);
    plaintext.fill(0);
    await rm(root, { recursive: true, force: true });
  }
});
