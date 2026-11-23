#!/usr/bin/env node

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  randomUUID,
  sign,
  verify
} from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import {
  encryptArtifact,
  generateSigningKeyPair,
  hashArtifactManifest,
  sha256,
  signArtifactManifest,
  type ArtifactManifest
} from '../../src/license-protocol.js';
import {
  appendDatabaseEvent,
  assertDatabaseAuditChain,
  encryptAtRest,
  hashSecret,
  mutateDatabase,
  readDatabase,
  verifyDatabaseEvents,
  withDatabaseLock,
  writeDatabase
} from './storage.js';

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function required(name: string): string {
  const value = argument(name);
  if (!value) throw new Error(`Missing --${name}.`);
  return value;
}

function tokenTtlMinutes(): number {
  const value = Number(argument('ttl-minutes') ?? '30');
  if (!Number.isInteger(value) || value < 1 || value > 1440) {
    throw new Error('--ttl-minutes must be an integer from 1 through 1440.');
  }
  return value;
}

function sha256Argument(name: string): string {
  const value = required(name).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(value)) throw new Error(`--${name} must be a SHA-256 hex digest.`);
  return value;
}

function githubReleaseUrl(value: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== 'https:' || parsed.hostname.toLowerCase() !== 'github.com') {
    throw new Error('--download-url must be an HTTPS github.com Release URL.');
  }
  if (!parsed.pathname.includes('/releases/download/')) {
    throw new Error('--download-url must point to a GitHub Release asset.');
  }
  const approvedRepository = process.env.HONGAI_RELEASE_REPOSITORY ?? 'kochmargarete77-create/HONGAI-Edge-Cage';
  const approvedPrefix = `/${approvedRepository}/releases/download/`.toLowerCase();
  if (!parsed.pathname.toLowerCase().startsWith(approvedPrefix)) {
    throw new Error(`--download-url must belong to the approved repository: ${approvedRepository}.`);
  }
  return parsed.href;
}

function dataRoot(): string {
  const value = required('data-root');
  if (!isAbsolute(value)) throw new Error('--data-root must be absolute.');
  return resolve(value);
}

async function masterKey(root: string): Promise<Buffer> {
  const encoded = (await readFile(resolve(root, 'master.key'), 'utf8')).trim();
  const key = Buffer.from(encoded, 'base64url');
  if (key.length !== 32) throw new Error('Invalid master.key.');
  return key;
}

async function signedArtifactManifest(
  root: string,
  value: Omit<ArtifactManifest, 'version'>
): Promise<{ manifest: ArtifactManifest; signature: string; hash: string }> {
  const manifest: ArtifactManifest = { version: 1, ...value };
  const signingPrivateKeyPem = await readFile(resolve(root, 'signing-private.pem'), 'utf8');
  return {
    manifest,
    signature: signArtifactManifest(manifest, signingPrivateKeyPem),
    hash: hashArtifactManifest(manifest)
  };
}

async function initialize(root: string): Promise<void> {
  await mkdir(root, { recursive: true });
  const signing = generateSigningKeyPair();
  await writeFile(resolve(root, 'signing-private.pem'), signing.privateKeyPem, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  await writeFile(resolve(root, 'signing-public.pem'), signing.publicKeyPem, { encoding: 'utf8', mode: 0o644, flag: 'wx' });
  await writeFile(resolve(root, 'master.key'), randomBytes(32).toString('base64url'), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  await writeDatabase(root, { version: 1, artifacts: [], licenses: [], tokens: [], activations: [], events: [] });
  console.log(JSON.stringify({ ok: true, dataRoot: root, publicKey: resolve(root, 'signing-public.pem') }, null, 2));
}

async function registerArtifact(root: string): Promise<void> {
  const contentKeyValue = process.env.HONGAI_ARTIFACT_CONTENT_KEY;
  if (!contentKeyValue) throw new Error('HONGAI_ARTIFACT_CONTENT_KEY is required.');
  const contentKey = Buffer.from(contentKeyValue, 'base64url');
  if (contentKey.length !== 32) throw new Error('Artifact content key must decode to 32 bytes.');
  const id = required('artifact-id');
  const downloadUrl = githubReleaseUrl(required('download-url'));
  const ciphertextSha256 = sha256Argument('ciphertext-sha256');
  const plaintextSha256 = sha256Argument('plaintext-sha256');
  const signedManifest = await signedArtifactManifest(root, {
    artifactId: id,
    downloadUrl,
    ciphertextSha256,
    plaintextSha256
  });
  const encryptionMasterKey = await masterKey(root);
  try {
    const encryptedContentKey = encryptAtRest(
      contentKey,
      encryptionMasterKey,
      Buffer.from(signedManifest.hash, 'hex')
    );
    await mutateDatabase(root, (database) => {
      if (database.artifacts.some((artifact) => artifact.id === id)) {
        throw new Error(`Artifact already exists: ${id}`);
      }
      database.artifacts.push({
        id,
        downloadUrl,
        ciphertextSha256,
        plaintextSha256,
        encryptedContentKey,
        manifest: signedManifest.manifest,
        manifestSignature: signedManifest.signature,
        enabled: true
      });
      appendDatabaseEvent(database, 'ARTIFACT_REGISTERED', 'admin', {
        artifactId: id,
        manifestSha256: signedManifest.hash
      });
    });
  } finally {
    encryptionMasterKey.fill(0);
    contentKey.fill(0);
  }
  console.log(JSON.stringify({ ok: true, artifactId: id }, null, 2));
}

async function encryptAndRegisterArtifact(root: string): Promise<void> {
  const inputPath = resolve(required('input'));
  const outputPath = resolve(required('output'));
  const artifactId = required('artifact-id');
  const downloadUrl = githubReleaseUrl(required('download-url'));
  const plaintext = await readFile(inputPath);
  const contentKey = randomBytes(32);
  const encrypted = encryptArtifact(plaintext, contentKey);
  const ciphertextSha256 = sha256(encrypted);
  const plaintextSha256 = sha256(plaintext);
  const signedManifest = await signedArtifactManifest(root, {
    artifactId,
    downloadUrl,
    ciphertextSha256,
    plaintextSha256
  });
  const encryptionMasterKey = await masterKey(root);
  let outputCreated = false;
  try {
    const encryptedContentKey = encryptAtRest(
      contentKey,
      encryptionMasterKey,
      Buffer.from(signedManifest.hash, 'hex')
    );
    await mutateDatabase(root, async (database) => {
      if (database.artifacts.some((artifact) => artifact.id === artifactId)) {
        throw new Error(`Artifact already exists: ${artifactId}`);
      }
      await mkdir(dirname(outputPath), { recursive: true });
      await writeFile(outputPath, encrypted, { mode: 0o600, flag: 'wx' });
      outputCreated = true;
      database.artifacts.push({
        id: artifactId,
        downloadUrl,
        ciphertextSha256,
        plaintextSha256,
        encryptedContentKey,
        manifest: signedManifest.manifest,
        manifestSignature: signedManifest.signature,
        enabled: true
      });
      appendDatabaseEvent(database, 'ARTIFACT_ENCRYPTED_AND_REGISTERED', 'admin', {
        artifactId,
        ciphertextSha256,
        manifestSha256: signedManifest.hash
      });
    });
  } catch (error) {
    if (outputCreated) {
      try {
        await rm(outputPath, { force: true });
      } catch (cleanupError) {
        throw new AggregateError([error, cleanupError], 'Artifact registration failed and encrypted-output cleanup also failed.');
      }
    }
    throw error;
  } finally {
    encryptionMasterKey.fill(0);
    contentKey.fill(0);
    plaintext.fill(0);
  }
  console.log(JSON.stringify({
    ok: true,
    artifactId,
    encryptedOutput: outputPath,
    ciphertextSha256,
    plaintextSha256
  }, null, 2));
}

function makeLicenseKey(licenseId: string): string {
  return `HA-LIC-${licenseId}.${randomBytes(24).toString('base64url')}`;
}

function makeOneTimeToken(tokenId: string): string {
  return `HA-OTP-${tokenId}.${randomBytes(24).toString('base64url')}`;
}

async function issue(root: string): Promise<void> {
  const artifactId = required('artifact-id');
  const licenseId = randomUUID();
  const tokenId = randomUUID();
  const licenseKey = makeLicenseKey(licenseId);
  const oneTimeToken = makeOneTimeToken(tokenId);
  const ttlMinutes = tokenTtlMinutes();
  const customerId = required('customer-id');
  await mutateDatabase(root, (database) => {
    if (!database.artifacts.some((artifact) => artifact.id === artifactId && artifact.enabled)) {
      throw new Error(`Unknown or disabled artifact: ${artifactId}`);
    }
    database.licenses.push({
      id: licenseId,
      customerId,
      licenseHash: hashSecret(licenseKey),
      allowedArtifacts: [artifactId],
      enabled: true,
      createdAt: new Date().toISOString()
    });
    database.tokens.push({
      id: tokenId,
      licenseId,
      tokenHash: hashSecret(oneTimeToken),
      expiresAt: new Date(Date.now() + ttlMinutes * 60_000).toISOString(),
      usedAt: null,
      revokedAt: null
    });
    appendDatabaseEvent(database, 'LICENSE_ISSUED', 'admin', {
      licenseId,
      customerId,
      artifactId
    });
  });
  console.log(JSON.stringify({
    ok: true,
    licenseId,
    licenseKey,
    oneTimeToken,
    expiresInMinutes: ttlMinutes,
    warning: 'These plaintext values are shown once. Transfer them through the approved secure channel.'
  }, null, 2));
}

async function issueToken(root: string): Promise<void> {
  const licenseId = required('license-id');
  const tokenId = randomUUID();
  const oneTimeToken = makeOneTimeToken(tokenId);
  const ttlMinutes = tokenTtlMinutes();
  await mutateDatabase(root, (database) => {
    if (!database.licenses.some((license) => license.id === licenseId && license.enabled)) {
      throw new Error('Unknown or disabled license ID.');
    }
    database.tokens.push({
      id: tokenId,
      licenseId,
      tokenHash: hashSecret(oneTimeToken),
      expiresAt: new Date(Date.now() + ttlMinutes * 60_000).toISOString(),
      usedAt: null,
      revokedAt: null
    });
    appendDatabaseEvent(database, 'ONE_TIME_TOKEN_ISSUED', 'admin', { licenseId, tokenId });
  });
  console.log(JSON.stringify({ ok: true, licenseId, oneTimeToken, expiresInMinutes: ttlMinutes }, null, 2));
}

async function revokeLicense(root: string): Promise<void> {
  const licenseId = required('license-id');
  const result = await mutateDatabase(root, (database) => {
    const license = database.licenses.find((candidate) => candidate.id === licenseId);
    if (!license) throw new Error('Unknown license ID.');
    if (!license.enabled) {
      return { alreadyRevoked: true, revokedTokens: 0 };
    }
    const now = new Date().toISOString();
    license.enabled = false;
    let revokedTokens = 0;
    for (const token of database.tokens) {
      if (token.licenseId === licenseId && !token.usedAt && !token.revokedAt) {
        token.revokedAt = now;
        revokedTokens += 1;
      }
    }
    appendDatabaseEvent(database, 'LICENSE_REVOKED', 'admin', { licenseId, revokedTokens });
    return { alreadyRevoked: false, revokedTokens };
  });
  console.log(JSON.stringify({ ok: true, licenseId, ...result }, null, 2));
}

async function status(root: string): Promise<void> {
  const licenseId = argument('license-id');
  const database = await readDatabase(root);
  assertDatabaseAuditChain(database);
  if (licenseId) {
    const license = database.licenses.find((candidate) => candidate.id === licenseId);
    if (!license) throw new Error('Unknown license ID.');
    const tokens = database.tokens.filter((candidate) => candidate.licenseId === licenseId);
    const activations = database.activations.filter((candidate) => candidate.licenseId === licenseId);
    console.log(JSON.stringify({
      ok: true,
      license: {
        id: license.id,
        customerId: license.customerId,
        enabled: license.enabled,
        allowedArtifacts: license.allowedArtifacts,
        createdAt: license.createdAt,
        tokenCounts: {
          total: tokens.length,
          pending: tokens.filter((token) => !token.usedAt && !token.revokedAt && Date.parse(token.expiresAt) >= Date.now()).length,
          used: tokens.filter((token) => Boolean(token.usedAt)).length,
          revoked: tokens.filter((token) => Boolean(token.revokedAt)).length
        },
        activationCounts: Object.fromEntries(
          ['KEY_ISSUED', 'DELIVERED', 'INSTALLED', 'FAILED'].map((result) => [
            result,
            activations.filter((activation) => activation.result === result).length
          ])
        )
      }
    }, null, 2));
    return;
  }
  console.log(JSON.stringify({
    ok: true,
    artifacts: { total: database.artifacts.length, enabled: database.artifacts.filter((item) => item.enabled).length },
    licenses: { total: database.licenses.length, enabled: database.licenses.filter((item) => item.enabled).length },
    tokens: { total: database.tokens.length },
    activations: { total: database.activations.length },
    auditEvents: database.events.length
  }, null, 2));
}

async function verifyAudit(root: string): Promise<void> {
  const database = await readDatabase(root);
  const ok = verifyDatabaseEvents(database.events);
  console.log(JSON.stringify({ ok, events: database.events.length }, null, 2));
  if (!ok) process.exitCode = 1;
}

interface AuditCheckpoint {
  version: 1;
  createdAt: string;
  databaseSha256: string;
  lastSequence: number;
  lastEventHash: string;
  signingKeySha256: string;
  signature: string;
}

function checkpointBytes(value: Omit<AuditCheckpoint, 'signature'>): Buffer {
  return Buffer.from(JSON.stringify(value), 'utf8');
}

async function createAuditCheckpoint(root: string): Promise<void> {
  const outputValue = required('output');
  if (!isAbsolute(outputValue)) throw new Error('--output must be absolute.');
  const outputPath = resolve(outputValue);
  const checkpoint = await withDatabaseLock(root, async () => {
    const database = await readDatabase(root);
    assertDatabaseAuditChain(database);
    const databaseBytes = await readFile(resolve(root, 'database.json'));
    const signingPrivateKeyPem = await readFile(resolve(root, 'signing-private.pem'), 'utf8');
    const signingPublicKeyPem = await readFile(resolve(root, 'signing-public.pem'), 'utf8');
    const lastEvent = database.events.at(-1);
    const unsigned: Omit<AuditCheckpoint, 'signature'> = {
      version: 1,
      createdAt: new Date().toISOString(),
      databaseSha256: createHash('sha256').update(databaseBytes).digest('hex'),
      lastSequence: lastEvent?.sequence ?? 0,
      lastEventHash: lastEvent?.hash ?? 'GENESIS',
      signingKeySha256: createHash('sha256')
        .update(createPublicKey(signingPublicKeyPem).export({ format: 'der', type: 'spki' }))
        .digest('hex')
    };
    return {
      ...unsigned,
      signature: sign(null, checkpointBytes(unsigned), createPrivateKey(signingPrivateKeyPem)).toString('base64url')
    };
  });
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(checkpoint, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'wx'
  });
  console.log(JSON.stringify({ ok: true, checkpoint: outputPath, sequence: checkpoint.lastSequence }, null, 2));
}

async function verifyAuditCheckpoint(root: string): Promise<void> {
  const checkpointValue = required('checkpoint');
  if (!isAbsolute(checkpointValue)) throw new Error('--checkpoint must be absolute.');
  const checkpointPath = resolve(checkpointValue);
  const checkpoint = JSON.parse(await readFile(checkpointPath, 'utf8')) as AuditCheckpoint;
  const { signature, ...unsigned } = checkpoint;
  const ok = await withDatabaseLock(root, async () => {
    const signingPublicKeyPem = await readFile(resolve(root, 'signing-public.pem'), 'utf8');
    const databaseBytes = await readFile(resolve(root, 'database.json'));
    const database = await readDatabase(root);
    const lastEvent = database.events.at(-1);
    const keyHash = createHash('sha256')
      .update(createPublicKey(signingPublicKeyPem).export({ format: 'der', type: 'spki' }))
      .digest('hex');
    return checkpoint.version === 1 &&
      verify(
        null,
        checkpointBytes(unsigned),
        createPublicKey(signingPublicKeyPem),
        Buffer.from(signature, 'base64url')
      ) &&
      checkpoint.databaseSha256 === createHash('sha256').update(databaseBytes).digest('hex') &&
      checkpoint.lastSequence === (lastEvent?.sequence ?? 0) &&
      checkpoint.lastEventHash === (lastEvent?.hash ?? 'GENESIS') &&
      checkpoint.signingKeySha256 === keyHash &&
      verifyDatabaseEvents(database.events);
  });
  console.log(JSON.stringify({ ok, checkpoint: checkpointPath, sequence: checkpoint.lastSequence }, null, 2));
  if (!ok) process.exitCode = 1;
}

async function main(): Promise<void> {
  const command = process.argv[2];
  const root = dataRoot();
  if (command === 'init') return await initialize(root);
  if (command === 'register-artifact') return await registerArtifact(root);
  if (command === 'encrypt-artifact') return await encryptAndRegisterArtifact(root);
  if (command === 'issue') return await issue(root);
  if (command === 'issue-token') return await issueToken(root);
  if (command === 'revoke-license') return await revokeLicense(root);
  if (command === 'status') return await status(root);
  if (command === 'verify-audit') return await verifyAudit(root);
  if (command === 'checkpoint') return await createAuditCheckpoint(root);
  if (command === 'verify-checkpoint') return await verifyAuditCheckpoint(root);
  throw new Error('Usage: license-admin <init|register-artifact|encrypt-artifact|issue|issue-token|revoke-license|status|verify-audit|checkpoint|verify-checkpoint> --data-root <absolute-path> ...');
}

main().catch((error: unknown) => {
  console.error(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exitCode = 1;
});
