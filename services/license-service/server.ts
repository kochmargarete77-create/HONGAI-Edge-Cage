#!/usr/bin/env node

import { createHash, createPrivateKey, createPublicKey, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { isAbsolute, resolve } from 'node:path';
import {
  hashArtifactManifest,
  signArtifactManifest,
  verifyArtifactManifestSignature,
  wrapContentKeyForInstall,
  type ArtifactManifest
} from '../../src/license-protocol.js';
import {
  appendDatabaseEvent,
  assertDatabaseAuditChain,
  decryptAtRest,
  hashSecret,
  mutateDatabase,
  readDatabase,
  verifySecret,
  type LicenseDatabase
} from './storage.js';

const rootValue = process.env.HONGAI_LICENSE_DATA_ROOT;
if (!rootValue || !isAbsolute(rootValue)) {
  throw new Error('HONGAI_LICENSE_DATA_ROOT must be an absolute path.');
}
const dataRoot = resolve(rootValue);
const bind = process.env.HONGAI_LICENSE_BIND ?? '127.0.0.1';
const port = Number(process.env.HONGAI_LICENSE_PORT ?? '8787');
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('HONGAI_LICENSE_PORT must be an integer from 1 through 65535.');
}
const loopbackBind = ['127.0.0.1', '::1', 'localhost'].includes(bind.toLowerCase());
if (!loopbackBind && process.env.HONGAI_LICENSE_ALLOW_PUBLIC_BIND !== '1') {
  throw new Error('Refusing a non-loopback HTTP bind without HONGAI_LICENSE_ALLOW_PUBLIC_BIND=1. Put TLS in front of this service.');
}
const auditPepper = process.env.HONGAI_LICENSE_AUDIT_PEPPER;
if (!auditPepper || auditPepper.length < 24) {
  throw new Error('HONGAI_LICENSE_AUDIT_PEPPER must contain at least 24 characters.');
}

let mutationQueue = Promise.resolve();
const rateWindows = new Map<string, number[]>();
const trustedProxy = process.env.HONGAI_LICENSE_TRUSTED_PROXY === '1';
const allowLegacyCredentials = process.env.HONGAI_LICENSE_ALLOW_LEGACY_KEYS !== '0';
const allowLegacyArtifacts = process.env.HONGAI_LICENSE_ALLOW_LEGACY_ARTIFACTS !== '0';

function json(response: ServerResponse, status: number, value: unknown): void {
  response.statusCode = status;
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.end(`${JSON.stringify(value)}\n`);
}

async function body(request: IncomingMessage): Promise<Record<string, unknown>> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk as Uint8Array);
    size += buffer.length;
    if (size > 32 * 1024) throw new Error('Request body is too large.');
    chunks.push(buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>;
}

function stringField(value: Record<string, unknown>, key: string, max = 4096): string {
  const field = value[key];
  if (typeof field !== 'string' || field.length < 1 || field.length > max) {
    throw new Error(`Invalid ${key}.`);
  }
  return field;
}

function remoteHash(request: IncomingMessage): string {
  const directAddress = request.socket.remoteAddress ?? 'unknown';
  const directIsLoopback = ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(directAddress);
  const forwarded = request.headers['x-forwarded-for'];
  const forwardedAddress = typeof forwarded === 'string' ? forwarded.split(',')[0]?.trim() : undefined;
  const remote = trustedProxy && directIsLoopback && forwardedAddress ? forwardedAddress : directAddress;
  return createHash('sha256').update(`${auditPepper}\0${remote}`).digest('hex');
}

function rateAllowed(key: string): boolean {
  const now = Date.now();
  if (rateWindows.size > 10_000) {
    for (const [candidate, times] of rateWindows) {
      if (!times.some((time) => now - time < 60_000)) rateWindows.delete(candidate);
    }
  }
  const existing = (rateWindows.get(key) ?? []).filter((time) => now - time < 60_000);
  existing.push(now);
  rateWindows.set(key, existing);
  return existing.length <= 10;
}

async function mutate<T>(callback: (database: LicenseDatabase) => Promise<T> | T): Promise<T> {
  let result: T;
  const task = mutationQueue.then(async () => {
    result = await mutateDatabase(dataRoot, callback);
  });
  mutationQueue = task.catch(() => {});
  await task;
  return result!;
}

function scopedSecretId(value: string, prefix: 'HA-LIC' | 'HA-OTP'): string | undefined {
  const marker = `${prefix}-`;
  if (!value.startsWith(marker)) return undefined;
  const separator = value.indexOf('.', marker.length);
  if (separator < 0) return undefined;
  const id = value.slice(marker.length, separator);
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)
    ? id
    : undefined;
}

function isLegacySecret(value: string, prefix: 'HA-LIC' | 'HA-OTP'): boolean {
  return new RegExp(`^${prefix}-[A-Za-z0-9_-]{32}$`).test(value);
}

async function activate(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const payload = await body(request);
  const licenseKey = stringField(payload, 'licenseKey', 256);
  const oneTimeToken = stringField(payload, 'oneTimeToken', 256);
  const artifactId = stringField(payload, 'artifactId', 160);
  const installId = stringField(payload, 'installId', 160);
  const clientPublicKeyPem = stringField(payload, 'clientPublicKeyPem', 4096);
  const signingPrivateKeyPem = await readFile(resolve(dataRoot, 'signing-private.pem'), 'utf8');
  const signingPublicKeyPem = await readFile(resolve(dataRoot, 'signing-public.pem'), 'utf8');
  const masterKey = Buffer.from((await readFile(resolve(dataRoot, 'master.key'), 'utf8')).trim(), 'base64url');

  const actorHash = remoteHash(request);
  const result = await mutate((database) => {
    const licenseId = scopedSecretId(licenseKey, 'HA-LIC');
    const tokenId = scopedSecretId(oneTimeToken, 'HA-OTP');
    const legacyCredentials = !licenseId || !tokenId;
    if (legacyCredentials && !allowLegacyCredentials) throw new Error('LICENSE_DENIED');
    if ((!licenseId && !isLegacySecret(licenseKey, 'HA-LIC')) || (!tokenId && !isLegacySecret(oneTimeToken, 'HA-OTP'))) {
      throw new Error('LICENSE_DENIED');
    }
    const license = licenseId
      ? database.licenses.find((candidate) => candidate.id === licenseId)
      : database.licenses.find((candidate) => candidate.enabled && verifySecret(licenseKey, candidate.licenseHash));
    if (!license?.enabled || (licenseId !== undefined && !verifySecret(licenseKey, license.licenseHash))) {
      throw new Error('LICENSE_DENIED');
    }
    if (!license || !license.allowedArtifacts.includes(artifactId)) throw new Error('LICENSE_DENIED');
    const token = database.tokens.find((candidate) =>
      (tokenId === undefined || candidate.id === tokenId) &&
      candidate.licenseId === license.id &&
      !candidate.usedAt &&
      !candidate.revokedAt &&
      Date.parse(candidate.expiresAt) >= Date.now() &&
      verifySecret(oneTimeToken, candidate.tokenHash)
    );
    if (!token) throw new Error('TOKEN_DENIED');
    const artifact = database.artifacts.find((candidate) => candidate.id === artifactId && candidate.enabled);
    if (!artifact) throw new Error('ARTIFACT_DENIED');
    const legacyArtifact = !artifact.manifest || !artifact.manifestSignature;
    if (legacyArtifact && !allowLegacyArtifacts) throw new Error('ARTIFACT_DENIED');
    const manifest: ArtifactManifest = artifact.manifest ?? {
      version: 1,
      artifactId: artifact.id,
      downloadUrl: artifact.downloadUrl,
      ciphertextSha256: artifact.ciphertextSha256,
      plaintextSha256: artifact.plaintextSha256
    };
    const manifestSignature = artifact.manifestSignature ?? signArtifactManifest(manifest, signingPrivateKeyPem);
    if (
      manifest.artifactId !== artifact.id ||
      manifest.downloadUrl !== artifact.downloadUrl ||
      manifest.ciphertextSha256 !== artifact.ciphertextSha256 ||
      manifest.plaintextSha256 !== artifact.plaintextSha256 ||
      !verifyArtifactManifestSignature(manifest, manifestSignature, signingPublicKeyPem)
    ) {
      throw new Error('ARTIFACT_DENIED');
    }
    const manifestSha256 = hashArtifactManifest(manifest);

    token.usedAt = new Date().toISOString();
    const activationId = randomUUID();
    const receiptToken = `HA-RCT-${randomBytes(24).toString('base64url')}`;
    database.activations.push({
      id: activationId,
      licenseId: license.id,
      artifactId,
      installIdHash: createHash('sha256').update(`${auditPepper}\0${installId}`).digest('hex'),
      receiptTokenHash: hashSecret(receiptToken),
      requestedAt: new Date().toISOString(),
      deliveredAt: null,
      completedAt: null,
      result: 'KEY_ISSUED'
    });
    appendDatabaseEvent(database, 'CONTENT_KEY_ISSUED', actorHash, {
      activationId,
      licenseId: license.id,
      artifactId,
      legacyCredentials,
      legacyArtifact,
      manifestSha256
    });
    const contentKey = decryptAtRest(
      artifact.encryptedContentKey,
      masterKey,
      legacyArtifact ? undefined : Buffer.from(manifestSha256, 'hex')
    );
    let envelope;
    try {
      envelope = wrapContentKeyForInstall({
        contentKey,
        artifactId,
        artifactManifestSha256: manifestSha256,
        installId,
        clientPublicKeyPem,
        signingPrivateKeyPem,
        ttlSeconds: 300
      });
    } finally {
      contentKey.fill(0);
    }
    return {
      activationId,
      receiptToken,
      artifact: {
        id: manifest.artifactId,
        downloadUrl: manifest.downloadUrl,
        ciphertextSha256: manifest.ciphertextSha256,
        plaintextSha256: manifest.plaintextSha256,
        manifestSignature
      },
      envelope
    };
  }).finally(() => masterKey.fill(0));
  json(response, 200, { ok: true, ...result });
}

async function receipt(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const payload = await body(request);
  const activationId = stringField(payload, 'activationId', 160);
  const receiptToken = stringField(payload, 'receiptToken', 256);
  const status = stringField(payload, 'status', 32);
  if (!['DELIVERED', 'INSTALLED', 'FAILED'].includes(status)) throw new Error('Invalid receipt status.');
  const actorHash = remoteHash(request);
  await mutate((database) => {
    const activation = database.activations.find((candidate) => candidate.id === activationId);
    if (!activation || !verifySecret(receiptToken, activation.receiptTokenHash)) {
      throw new Error('RECEIPT_DENIED');
    }
    if (activation.result === status) return;
    if (activation.result === 'INSTALLED' || activation.result === 'FAILED') {
      throw new Error('RECEIPT_TRANSITION_DENIED');
    }
    const now = new Date().toISOString();
    if (status === 'DELIVERED') {
      activation.deliveredAt = now;
      activation.result = 'DELIVERED';
    } else if (status === 'INSTALLED') {
      activation.deliveredAt ??= now;
      activation.completedAt = now;
      activation.result = 'INSTALLED';
    } else {
      activation.completedAt = now;
      activation.result = 'FAILED';
    }
    appendDatabaseEvent(database, `ARTIFACT_${status}`, actorHash, {
      activationId,
      artifactId: activation.artifactId
    });
  });
  json(response, 200, { ok: true, activationId, status });
}

const server = createServer(async (request, response) => {
  try {
    if (request.method === 'GET' && request.url === '/health') {
      json(response, 200, { ok: true, service: 'HONG AI Edge Cage License Service' });
      return;
    }
    const requestKey = remoteHash(request);
    if (!rateAllowed(requestKey)) {
      json(response, 429, { ok: false, error: 'RATE_LIMITED' });
      return;
    }
    if (request.method === 'POST' && request.url === '/v1/activate') {
      if (!request.headers['content-type']?.toLowerCase().startsWith('application/json')) {
        json(response, 415, { ok: false, error: 'JSON_REQUIRED' });
        return;
      }
      await activate(request, response);
      return;
    }
    if (request.method === 'POST' && request.url === '/v1/receipt') {
      if (!request.headers['content-type']?.toLowerCase().startsWith('application/json')) {
        json(response, 415, { ok: false, error: 'JSON_REQUIRED' });
        return;
      }
      await receipt(request, response);
      return;
    }
    json(response, 404, { ok: false, error: 'NOT_FOUND' });
  } catch (error) {
    const code = error instanceof Error ? error.message : 'INTERNAL_ERROR';
    const safeCode = /^[A-Z_]+$/.test(code) ? code : 'INVALID_REQUEST';
    json(response, safeCode.endsWith('DENIED') ? 403 : 400, { ok: false, error: safeCode });
  }
});
server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.keepAliveTimeout = 5_000;
server.maxRequestsPerSocket = 100;

async function validateServiceState(): Promise<void> {
  const database = await readDatabase(dataRoot);
  assertDatabaseAuditChain(database);
  const encodedMasterKey = (await readFile(resolve(dataRoot, 'master.key'), 'utf8')).trim();
  const masterKey = Buffer.from(encodedMasterKey, 'base64url');
  try {
    if (masterKey.length !== 32) throw new Error('License-service master key is invalid.');
  } finally {
    masterKey.fill(0);
  }
  const signingPrivateKeyPem = await readFile(resolve(dataRoot, 'signing-private.pem'), 'utf8');
  const signingPrivateKey = createPrivateKey(signingPrivateKeyPem);
  if (signingPrivateKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('License-service signing key must be Ed25519.');
  }
  const signingPublicKeyPem = await readFile(resolve(dataRoot, 'signing-public.pem'), 'utf8');
  const derivedPublicKey = createPublicKey(signingPrivateKey).export({ format: 'der', type: 'spki' });
  const configuredPublicKey = createPublicKey(signingPublicKeyPem).export({ format: 'der', type: 'spki' });
  if (!Buffer.from(derivedPublicKey).equals(Buffer.from(configuredPublicKey))) {
    throw new Error('License-service signing public and private keys do not match.');
  }
  for (const artifact of database.artifacts) {
    if (!artifact.manifest || !artifact.manifestSignature) {
      if (!allowLegacyArtifacts) throw new Error(`Legacy artifact must be re-registered: ${artifact.id}`);
      continue;
    }
    if (
      artifact.manifest.artifactId !== artifact.id ||
      artifact.manifest.downloadUrl !== artifact.downloadUrl ||
      artifact.manifest.ciphertextSha256 !== artifact.ciphertextSha256 ||
      artifact.manifest.plaintextSha256 !== artifact.plaintextSha256 ||
      !verifyArtifactManifestSignature(artifact.manifest, artifact.manifestSignature, signingPublicKeyPem)
    ) {
      throw new Error(`Artifact manifest validation failed: ${artifact.id}`);
    }
  }
}

validateServiceState().then(() => {
  server.listen(port, bind, () => {
    console.log(`HONG AI license service listening on http://${bind}:${port}`);
  });
}).catch((error: unknown) => {
  console.error(JSON.stringify({
    ok: false,
    error: error instanceof Error ? error.message : String(error)
  }));
  process.exitCode = 1;
});
