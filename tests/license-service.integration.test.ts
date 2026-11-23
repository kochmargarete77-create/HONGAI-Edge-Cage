import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { generateInstallIdentity } from '../src/license-protocol.js';
import { verifyDatabaseEvents, type LicenseDatabase } from '../services/license-service/storage.js';

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const adminPath = resolve(projectRoot, 'dist', 'services', 'license-service', 'admin.js');
const serverPath = resolve(projectRoot, 'dist', 'services', 'license-service', 'server.js');

function runAdmin(arguments_: string[]): string {
  const result = spawnSync(process.execPath, [adminPath, ...arguments_], {
    cwd: projectRoot,
    encoding: 'utf8',
    windowsHide: true
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolveListen, reject) => {
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', resolveListen);
  });
  const address = probe.address();
  assert.ok(address && typeof address !== 'string');
  await new Promise<void>((resolveClose) => probe.close(() => resolveClose()));
  return address.port;
}

async function waitUntilReady(baseUrl: string, child: ChildProcess): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (child.exitCode !== null) throw new Error('License service exited before readiness.');
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) return;
    } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  throw new Error('License service did not become ready.');
}

test('license service consumes one-time tokens and records delivery in its audit chain', async () => {
  const tempBase = resolve(projectRoot, '.tmp');
  await mkdir(tempBase, { recursive: true });
  const dataRoot = await mkdtemp(resolve(tempBase, 'license-service-test-'));
  const port = await freePort();
  let child: ChildProcess | undefined;
  try {
    runAdmin(['init', '--data-root', dataRoot]);
    runAdmin([
      'encrypt-artifact',
      '--data-root', dataRoot,
      '--artifact-id', 'integration-artifact',
      '--input', resolve(projectRoot, 'README.md'),
      '--output', resolve(dataRoot, 'integration-artifact.enc'),
      '--download-url', 'https://github.com/kochmargarete77-create/HONGAI-Edge-Cage/releases/download/test/integration-artifact.enc'
    ]);
    const issued = JSON.parse(runAdmin([
      'issue',
      '--data-root', dataRoot,
      '--customer-id', 'integration-customer',
      '--artifact-id', 'integration-artifact',
      '--ttl-minutes', '5'
    ])) as { licenseId: string; licenseKey: string; oneTimeToken: string };

    child = spawn(process.execPath, [serverPath], {
      cwd: projectRoot,
      env: {
        ...process.env,
        HONGAI_LICENSE_DATA_ROOT: dataRoot,
        HONGAI_LICENSE_BIND: '127.0.0.1',
        HONGAI_LICENSE_PORT: String(port),
        HONGAI_LICENSE_AUDIT_PEPPER: 'integration-only-pepper-32-characters'
      },
      stdio: 'ignore',
      windowsHide: true
    });
    const baseUrl = `http://127.0.0.1:${port}`;
    await waitUntilReady(baseUrl, child);
    const identity = generateInstallIdentity();
    const activationBody = {
      licenseKey: issued.licenseKey,
      oneTimeToken: issued.oneTimeToken,
      activationProtocolVersion: 2,
      artifactId: 'integration-artifact',
      installId: identity.installId,
      clientPublicKeyPem: identity.publicKeyPem
    };
    const activationResponse = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(activationBody)
    });
    assert.equal(activationResponse.status, 200);
    const activation = await activationResponse.json() as {
      ok: boolean;
      activationId: string;
      receiptToken: string;
      recoveryToken: string;
      envelope: { issuedAt: string; expiresAt: string };
    };
    assert.equal(activation.ok, true);

    // A lost HTTP response must not burn the OTP. Repeating the exact binding
    // returns the same activation credentials and a freshly signed envelope.
    const retryResponse = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(activationBody)
    });
    assert.equal(retryResponse.status, 200);
    const retry = await retryResponse.json() as typeof activation;
    assert.equal(retry.activationId, activation.activationId);
    assert.equal(retry.receiptToken, activation.receiptToken);
    assert.equal(retry.recoveryToken, activation.recoveryToken);

    const resumeResponse = await fetch(`${baseUrl}/v1/activation/resume`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        licenseKey: issued.licenseKey,
        activationId: activation.activationId,
        recoveryToken: activation.recoveryToken,
        artifactId: 'integration-artifact',
        installId: identity.installId,
        clientPublicKeyPem: identity.publicKeyPem
      })
    });
    assert.equal(resumeResponse.status, 200);
    const resumed = await resumeResponse.json() as typeof activation;
    assert.equal(resumed.activationId, activation.activationId);
    assert.equal(resumed.receiptToken, activation.receiptToken);
    assert.equal(resumed.recoveryToken, activation.recoveryToken);

    const otherIdentity = generateInstallIdentity();
    const reboundResponse = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...activationBody,
        installId: otherIdentity.installId,
        clientPublicKeyPem: otherIdentity.publicKeyPem
      })
    });
    assert.equal(reboundResponse.status, 403);

    const receiptResponse = await fetch(`${baseUrl}/v1/receipt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationId: activation.activationId,
        receiptToken: activation.receiptToken,
        status: 'DELIVERED'
      })
    });
    assert.equal(receiptResponse.status, 200);
    const duplicateReceiptResponse = await fetch(`${baseUrl}/v1/receipt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationId: activation.activationId,
        receiptToken: activation.receiptToken,
        status: 'DELIVERED'
      })
    });
    assert.equal(duplicateReceiptResponse.status, 200);
    const installedReceiptResponse = await fetch(`${baseUrl}/v1/receipt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationId: activation.activationId,
        receiptToken: activation.receiptToken,
        status: 'INSTALLED'
      })
    });
    assert.equal(installedReceiptResponse.status, 200);
    const terminalDowngradeResponse = await fetch(`${baseUrl}/v1/receipt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        activationId: activation.activationId,
        receiptToken: activation.receiptToken,
        status: 'DELIVERED'
      })
    });
    assert.equal(terminalDowngradeResponse.status, 403);

    const replayResponse = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(activationBody)
    });
    assert.equal(replayResponse.status, 403);

    const replacement = JSON.parse(runAdmin([
      'issue-token',
      '--data-root', dataRoot,
      '--license-id', issued.licenseId,
      '--ttl-minutes', '5'
    ])) as { oneTimeToken: string };
    const revoked = JSON.parse(runAdmin([
      'revoke-license',
      '--data-root', dataRoot,
      '--license-id', issued.licenseId
    ])) as { ok: boolean; revokedTokens: number };
    assert.equal(revoked.ok, true);
    assert.equal(revoked.revokedTokens, 1);
    const revokedResponse = await fetch(`${baseUrl}/v1/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...activationBody, oneTimeToken: replacement.oneTimeToken })
    });
    assert.equal(revokedResponse.status, 403);

    const checkpointPath = resolve(dataRoot, 'audit-checkpoint.json');
    runAdmin([
      'checkpoint',
      '--data-root', dataRoot,
      '--output', checkpointPath
    ]);
    runAdmin([
      'verify-checkpoint',
      '--data-root', dataRoot,
      '--checkpoint', checkpointPath
    ]);

    const database = JSON.parse(
      await readFile(resolve(dataRoot, 'database.json'), 'utf8')
    ) as LicenseDatabase;
    assert.equal(database.activations.length, 1);
    assert.equal(database.activations[0]?.result, 'INSTALLED');
    const recoverable = database.activations[0] as (LicenseDatabase['activations'][number] & {
      protocolVersion?: number;
      tokenId?: string;
      activationBindingSha256?: string;
      artifactManifestSha256?: string;
      recoveryTokenHash?: unknown;
      recoveryExpiresAt?: string;
    });
    assert.equal(recoverable.protocolVersion, 2);
    assert.equal(typeof recoverable.tokenId, 'string');
    assert.match(recoverable.activationBindingSha256 ?? '', /^[a-f0-9]{64}$/);
    assert.match(recoverable.artifactManifestSha256 ?? '', /^[a-f0-9]{64}$/);
    assert.ok(recoverable.recoveryTokenHash);
    assert.ok(Date.parse(recoverable.recoveryExpiresAt ?? '') > Date.now());
    assert.equal(database.events.some((event) => event.type === 'ACTIVATION_ENVELOPE_RENEWED'), true);
    assert.equal(verifyDatabaseEvents(database.events), true);
  } finally {
    if (child && child.exitCode === null) {
      child.kill();
      await new Promise<void>((resolveExit) => {
        child!.once('exit', () => resolveExit());
        setTimeout(resolveExit, 2_000).unref();
      });
    }
    const resolvedRoot = resolve(dataRoot);
    assert.ok(resolvedRoot.startsWith(`${resolve(tempBase)}${process.platform === 'win32' ? '\\' : '/'}`));
    await rm(resolvedRoot, { recursive: true, force: true });
  }
});
