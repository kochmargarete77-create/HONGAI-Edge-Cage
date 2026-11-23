#!/usr/bin/env node

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { isAbsolute, resolve } from 'node:path';
import { wrapContentKeyForInstall } from '../../src/license-protocol.js';
import {
  appendDatabaseEvent,
  assertDatabaseAuditChain,
  decryptAtRest,
  hashSecret,
  readDatabase,
  verifySecret,
  writeDatabase,
  type LicenseDatabase
} from './storage.js';

const rootValue = process.env.HONGAI_LICENSE_DATA_ROOT;
if (!rootValue || !isAbsolute(rootValue)) {
  throw new Error('HONGAI_LICENSE_DATA_ROOT must be an absolute path.');
}
const dataRoot = resolve(rootValue);
const bind = process.env.HONGAI_LICENSE_BIND ?? '127.0.0.1';
const port = Number(process.env.HONGAI_LICENSE_PORT ?? '8787');
const auditPepper = process.env.HONGAI_LICENSE_AUDIT_PEPPER;
if (!auditPepper || auditPepper.length < 24) {
  throw new Error('HONGAI_LICENSE_AUDIT_PEPPER must contain at least 24 characters.');
}

let mutationQueue = Promise.resolve();
const rateWindows = new Map<string, number[]>();
const trustedProxy = process.env.HONGAI_LICENSE_TRUSTED_PROXY === '1';

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
    const database = await readDatabase(dataRoot);
    assertDatabaseAuditChain(database);
    result = await callback(database);
    await writeDatabase(dataRoot, database);
  });
  mutationQueue = task.catch(() => {});
  await task;
  return result!;
}

async function activate(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const payload = await body(request);
  const licenseKey = stringField(payload, 'licenseKey', 256);
  const oneTimeToken = stringField(payload, 'oneTimeToken', 256);
  const artifactId = stringField(payload, 'artifactId', 160);
  const installId = stringField(payload, 'installId', 160);
  const clientPublicKeyPem = stringField(payload, 'clientPublicKeyPem', 4096);
  const signingPrivateKeyPem = await readFile(resolve(dataRoot, 'signing-private.pem'), 'utf8');
  const masterKey = Buffer.from((await readFile(resolve(dataRoot, 'master.key'), 'utf8')).trim(), 'base64url');

  const actorHash = remoteHash(request);
  const result = await mutate((database) => {
    const license = database.licenses.find((candidate) =>
      candidate.enabled && verifySecret(licenseKey, candidate.licenseHash)
    );
    if (!license || !license.allowedArtifacts.includes(artifactId)) throw new Error('LICENSE_DENIED');
    const token = database.tokens.find((candidate) =>
      candidate.licenseId === license.id &&
      !candidate.usedAt &&
      Date.parse(candidate.expiresAt) >= Date.now() &&
      verifySecret(oneTimeToken, candidate.tokenHash)
    );
    if (!token) throw new Error('TOKEN_DENIED');
    const artifact = database.artifacts.find((candidate) => candidate.id === artifactId && candidate.enabled);
    if (!artifact) throw new Error('ARTIFACT_DENIED');

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
      artifactId
    });
    const contentKey = decryptAtRest(artifact.encryptedContentKey, masterKey);
    const envelope = wrapContentKeyForInstall({
      contentKey,
      artifactId,
      installId,
      clientPublicKeyPem,
      signingPrivateKeyPem,
      ttlSeconds: 300
    });
    contentKey.fill(0);
    return {
      activationId,
      receiptToken,
      artifact: {
        id: artifact.id,
        downloadUrl: artifact.downloadUrl,
        ciphertextSha256: artifact.ciphertextSha256,
        plaintextSha256: artifact.plaintextSha256
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
    if (status === 'DELIVERED') {
      if (activation.deliveredAt) throw new Error('DELIVERY_ALREADY_RECORDED');
      activation.deliveredAt = new Date().toISOString();
      activation.result = 'DELIVERED';
    } else {
      if (activation.completedAt) throw new Error('RECEIPT_ALREADY_RECORDED');
      activation.completedAt = new Date().toISOString();
      activation.result = status as 'INSTALLED' | 'FAILED';
    }
    appendDatabaseEvent(database, `ARTIFACT_${status}`, actorHash, {
      activationId,
      artifactId: activation.artifactId
    });
  });
  json(response, 200, { ok: true, activationId, status });
}

const server = createServer(async (request, response) => {
  const requestKey = remoteHash(request);
  if (!rateAllowed(requestKey)) {
    json(response, 429, { ok: false, error: 'RATE_LIMITED' });
    return;
  }
  try {
    if (request.method === 'GET' && request.url === '/health') {
      json(response, 200, { ok: true, service: 'HONG AI Edge Cage License Service' });
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

server.listen(port, bind, () => {
  console.log(`HONG AI license service listening on http://${bind}:${port}`);
});
