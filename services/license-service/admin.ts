#!/usr/bin/env node

import { randomBytes, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import {
  encryptArtifact,
  generateSigningKeyPair,
  sha256
} from '../../src/license-protocol.js';
import {
  appendDatabaseEvent,
  assertDatabaseAuditChain,
  encryptAtRest,
  hashSecret,
  readDatabase,
  verifyDatabaseEvents,
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

function githubReleaseUrl(value: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== 'https:' || parsed.hostname.toLowerCase() !== 'github.com') {
    throw new Error('--download-url must be an HTTPS github.com Release URL.');
  }
  if (!parsed.pathname.includes('/releases/download/')) {
    throw new Error('--download-url must point to a GitHub Release asset.');
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
  const database = await readDatabase(root);
  assertDatabaseAuditChain(database);
  const id = required('artifact-id');
  if (database.artifacts.some((artifact) => artifact.id === id)) {
    throw new Error(`Artifact already exists: ${id}`);
  }
  const downloadUrl = githubReleaseUrl(required('download-url'));
  const encryptionMasterKey = await masterKey(root);
  const encryptedContentKey = encryptAtRest(contentKey, encryptionMasterKey);
  encryptionMasterKey.fill(0);
  database.artifacts.push({
    id,
    downloadUrl,
    ciphertextSha256: required('ciphertext-sha256'),
    plaintextSha256: required('plaintext-sha256'),
    encryptedContentKey,
    enabled: true
  });
  appendDatabaseEvent(database, 'ARTIFACT_REGISTERED', 'admin', { artifactId: id });
  await writeDatabase(root, database);
  contentKey.fill(0);
  console.log(JSON.stringify({ ok: true, artifactId: id }, null, 2));
}

async function encryptAndRegisterArtifact(root: string): Promise<void> {
  const inputPath = resolve(required('input'));
  const outputPath = resolve(required('output'));
  const artifactId = required('artifact-id');
  const downloadUrl = githubReleaseUrl(required('download-url'));
  const database = await readDatabase(root);
  assertDatabaseAuditChain(database);
  if (database.artifacts.some((artifact) => artifact.id === artifactId)) {
    throw new Error(`Artifact already exists: ${artifactId}`);
  }
  const plaintext = await readFile(inputPath);
  const contentKey = randomBytes(32);
  const encrypted = encryptArtifact(plaintext, contentKey);
  const ciphertextSha256 = sha256(encrypted);
  const plaintextSha256 = sha256(plaintext);
  const encryptionMasterKey = await masterKey(root);
  const encryptedContentKey = encryptAtRest(contentKey, encryptionMasterKey);
  encryptionMasterKey.fill(0);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, encrypted, { mode: 0o600, flag: 'wx' });
  database.artifacts.push({
    id: artifactId,
    downloadUrl,
    ciphertextSha256,
    plaintextSha256,
    encryptedContentKey,
    enabled: true
  });
  contentKey.fill(0);
  appendDatabaseEvent(database, 'ARTIFACT_ENCRYPTED_AND_REGISTERED', 'admin', {
    artifactId,
    ciphertextSha256
  });
  await writeDatabase(root, database);
  plaintext.fill(0);
  console.log(JSON.stringify({
    ok: true,
    artifactId,
    encryptedOutput: outputPath,
    ciphertextSha256,
    plaintextSha256
  }, null, 2));
}

function makeLicenseKey(): string {
  return `HA-LIC-${randomBytes(24).toString('base64url')}`;
}

function makeOneTimeToken(): string {
  return `HA-OTP-${randomBytes(24).toString('base64url')}`;
}

async function issue(root: string): Promise<void> {
  const database = await readDatabase(root);
  assertDatabaseAuditChain(database);
  const artifactId = required('artifact-id');
  if (!database.artifacts.some((artifact) => artifact.id === artifactId && artifact.enabled)) {
    throw new Error(`Unknown or disabled artifact: ${artifactId}`);
  }
  const licenseKey = makeLicenseKey();
  const oneTimeToken = makeOneTimeToken();
  const licenseId = randomUUID();
  const ttlMinutes = tokenTtlMinutes();
  const customerId = required('customer-id');
  database.licenses.push({
    id: licenseId,
    customerId,
    licenseHash: hashSecret(licenseKey),
    allowedArtifacts: [artifactId],
    enabled: true,
    createdAt: new Date().toISOString()
  });
  database.tokens.push({
    id: randomUUID(),
    licenseId,
    tokenHash: hashSecret(oneTimeToken),
    expiresAt: new Date(Date.now() + ttlMinutes * 60_000).toISOString(),
    usedAt: null
  });
  appendDatabaseEvent(database, 'LICENSE_ISSUED', 'admin', {
    licenseId,
    customerId,
    artifactId
  });
  await writeDatabase(root, database);
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
  const database = await readDatabase(root);
  assertDatabaseAuditChain(database);
  const licenseId = required('license-id');
  if (!database.licenses.some((license) => license.id === licenseId && license.enabled)) {
    throw new Error('Unknown or disabled license ID.');
  }
  const oneTimeToken = makeOneTimeToken();
  const ttlMinutes = tokenTtlMinutes();
  database.tokens.push({
    id: randomUUID(),
    licenseId,
    tokenHash: hashSecret(oneTimeToken),
    expiresAt: new Date(Date.now() + ttlMinutes * 60_000).toISOString(),
    usedAt: null
  });
  appendDatabaseEvent(database, 'ONE_TIME_TOKEN_ISSUED', 'admin', { licenseId });
  await writeDatabase(root, database);
  console.log(JSON.stringify({ ok: true, licenseId, oneTimeToken, expiresInMinutes: ttlMinutes }, null, 2));
}

async function verifyAudit(root: string): Promise<void> {
  const database = await readDatabase(root);
  const ok = verifyDatabaseEvents(database.events);
  console.log(JSON.stringify({ ok, events: database.events.length }, null, 2));
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
  if (command === 'verify-audit') return await verifyAudit(root);
  throw new Error('Usage: license-admin <init|register-artifact|encrypt-artifact|issue|issue-token|verify-audit> --data-root <absolute-path> ...');
}

main().catch((error: unknown) => {
  console.error(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exitCode = 1;
});
