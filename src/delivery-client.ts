import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  scryptSync
} from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { link, lstat, mkdir, open, rename, rm } from 'node:fs/promises';
import { dirname, isAbsolute } from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fetch as undiciFetch, ProxyAgent, type Dispatcher } from 'undici';
import { z } from 'zod';
import {
  encryptedArtifactAad,
  generateInstallIdentity,
  hashArtifactManifest,
  parseEncryptedArtifactHeader,
  sha256,
  unwrapContentKey,
  verifyArtifactManifestSignature,
  type ArtifactManifest,
  type ContentKeyEnvelope
} from './license-protocol.js';

const envelopeSchema = z.object({
  version: z.literal(2),
  artifactId: z.string().min(1),
  artifactManifestSha256: z.string().regex(/^[a-f0-9]{64}$/),
  installId: z.string().min(1),
  issuedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  ephemeralPublicKeyPem: z.string().min(1),
  salt: z.string().min(1),
  iv: z.string().min(1),
  ciphertext: z.string().min(1),
  authTag: z.string().min(1),
  signature: z.string().min(1)
}).strict();

const activationSchema = z.object({
  ok: z.literal(true),
  activationId: z.string().min(1),
  receiptToken: z.string().min(1),
  recoveryToken: z.string().min(1).max(256).optional(),
  artifact: z.object({
    id: z.string().min(1),
    downloadUrl: z.string().url(),
    ciphertextSha256: z.string().regex(/^[a-f0-9]{64}$/),
    plaintextSha256: z.string().regex(/^[a-f0-9]{64}$/),
    manifestSignature: z.string().min(1)
  }).strict(),
  envelope: envelopeSchema
}).strict();

const activationRecoveryStateSchema = z.object({
  version: z.literal(1),
  serviceUrl: z.string().url(),
  artifactId: z.string().min(1).max(160),
  signingPublicKeySha256: z.string().regex(/^[a-f0-9]{64}$/),
  installId: z.string().min(1).max(160),
  clientPublicKeyPem: z.string().min(1).max(4096),
  clientPrivateKeyPem: z.string().min(1).max(4096),
  activationId: z.string().min(1).max(160).optional(),
  recoveryToken: z.string().min(1).max(256).optional(),
  receiptToken: z.string().min(1).max(256).optional(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime()
}).strict();

const encryptedActivationRecoverySchema = z.object({
  version: z.literal(1),
  kdf: z.object({
    name: z.literal('scrypt'),
    N: z.literal(16_384),
    r: z.literal(8),
    p: z.literal(1)
  }).strict(),
  cipher: z.literal('aes-256-gcm'),
  salt: z.string().regex(/^[A-Za-z0-9_-]+$/),
  iv: z.string().regex(/^[A-Za-z0-9_-]+$/),
  ciphertext: z.string().regex(/^[A-Za-z0-9_-]+$/).max(64_000),
  authTag: z.string().regex(/^[A-Za-z0-9_-]+$/)
}).strict();

const pendingReceiptSchema = z.object({
  version: z.literal(1),
  serviceUrl: z.string().url(),
  activationId: z.string().min(1).max(160),
  receiptToken: z.string().min(1).max(256),
  status: z.enum(['DELIVERED', 'INSTALLED', 'FAILED']),
  proxyUrl: z.string().url().optional(),
  createdAt: z.string().datetime()
}).strict();

const encryptedPendingReceiptSchema = z.object({
  version: z.literal(1),
  kdf: z.object({
    name: z.literal('scrypt'),
    N: z.literal(16_384),
    r: z.literal(8),
    p: z.literal(1)
  }).strict(),
  cipher: z.literal('aes-256-gcm'),
  salt: z.string().regex(/^[A-Za-z0-9_-]+$/),
  iv: z.string().regex(/^[A-Za-z0-9_-]+$/),
  ciphertext: z.string().regex(/^[A-Za-z0-9_-]+$/).max(32_768),
  authTag: z.string().regex(/^[A-Za-z0-9_-]+$/)
}).strict();

const pendingReceiptAad = Buffer.from('HONG-AI-EDGE-CAGE-RECEIPT-OUTBOX-V1', 'utf8');
const activationRecoveryAad = Buffer.from('HONG-AI-EDGE-CAGE-ACTIVATION-RECOVERY-V1', 'utf8');
const maximumPendingReceiptBytes = 64 * 1024;
const maximumActivationRecoveryBytes = 96 * 1024;
const pendingReceiptScrypt = { N: 16_384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 } as const;

export interface RetrieveArtifactOptions {
  serviceUrl: string;
  artifactId: string;
  licenseKey: string;
  oneTimeToken: string;
  signingPublicKeyPem: string;
  outputPath: string;
  proxyUrl?: string;
  activationRecoveryPath?: string;
  maximumBytes?: number;
  finalize?: (artifact: RetrievedArtifact) => Promise<void>;
}

export function assertApprovedDeliveryProxyUrl(value: string): URL {
  const url = new URL(value);
  const loopback = ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(url.hostname.toLowerCase());
  if (
    !['http:', 'https:'].includes(url.protocol)
    || !loopback
    || !url.port
    || url.username
    || url.password
    || (url.pathname !== '/' && url.pathname !== '')
    || url.search
    || url.hash
  ) {
    throw new Error('Delivery proxy must be an unauthenticated HTTP(S) loopback URL with an explicit port.');
  }
  return url;
}

function deliveryProxyAgent(value: string): ProxyAgent {
  return new ProxyAgent(assertApprovedDeliveryProxyUrl(value).href);
}

function fetchThrough(
  input: string | URL,
  init: RequestInit,
  dispatcher?: Dispatcher
): Promise<Response> {
  if (!dispatcher) return globalThis.fetch(input, init);
  // A Dispatcher created by the pinned undici package must be paired with that
  // package's fetch implementation. Node's embedded fetch may use a different
  // undici ABI even on the same Node major version.
  return undiciFetch(input, { ...init, dispatcher } as Parameters<typeof undiciFetch>[1]) as unknown as Promise<Response>;
}

export interface RetrievedArtifact {
  activationId: string;
  artifactId: string;
  outputPath: string;
  plaintextSha256: string;
  bytes: number;
}

export interface RetrieveArtifactResult extends RetrievedArtifact {
  receiptRecorded: boolean;
  receiptPendingPath: string | null;
  deliveryState: 'RECEIPT_RECORDED' | 'PENDING_RECEIPT';
  status: 'DELIVERED' | 'INSTALLED';
}

function serviceEndpoint(serviceUrl: string, pathname: string): URL {
  const base = new URL(serviceUrl);
  const isLoopback = ['127.0.0.1', 'localhost', '::1', '[::1]'].includes(base.hostname);
  if (base.protocol !== 'https:' && !(base.protocol === 'http:' && isLoopback)) {
    throw new Error('License service must use HTTPS; HTTP is allowed only on loopback for development.');
  }
  return new URL(pathname, base.href.endsWith('/') ? base : `${base.href}/`);
}

export function assertApprovedReleaseUrl(value: string): URL {
  const url = new URL(value);
  const approvedHosts = new Set([
    'github.com',
    'objects.githubusercontent.com',
    'release-assets.githubusercontent.com',
    'github-releases.githubusercontent.com'
  ]);
  if (url.protocol !== 'https:' || !approvedHosts.has(url.hostname.toLowerCase())) {
    throw new Error('Artifact URL must be an HTTPS GitHub Release URL.');
  }
  return url;
}

type ActivationRecoveryState = z.infer<typeof activationRecoveryStateSchema>;

class LicenseServiceRefusalError extends Error {
  constructor(
    readonly refusalCode: string,
    readonly httpStatus: number
  ) {
    super(`License service refused the request: ${refusalCode}`);
    this.name = 'LicenseServiceRefusalError';
  }
}

function isDefiniteNonRetryableActivationRefusal(error: LicenseServiceRefusalError): boolean {
  // Preserve the bound install identity for all server failures and transient
  // or concurrency-related client responses. Only ordinary, non-retryable
  // client faults prove that no successful activation response can be
  // recovered with this newly-created identity.
  return [400, 401, 403, 404, 405, 410, 413, 415, 422].includes(error.httpStatus);
}

function canonicalServiceUrl(value: string): string {
  serviceEndpoint(value, 'v1/activate');
  const url = new URL(value);
  return url.href.endsWith('/') ? url.href : `${url.href}/`;
}

function signingPublicKeySha256(pem: string): string {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error('Delivery signing public key must be Ed25519.');
  }
  return sha256(Buffer.from(key.export({ format: 'der', type: 'spki' })));
}

function validateRecoveryIdentity(state: ActivationRecoveryState): void {
  const privateKey = createPrivateKey(state.clientPrivateKeyPem);
  const publicKey = createPublicKey(state.clientPublicKeyPem);
  if (privateKey.asymmetricKeyType !== 'x25519' || publicKey.asymmetricKeyType !== 'x25519') {
    throw new Error('Activation recovery identity must use X25519 keys.');
  }
  const derived = Buffer.from(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }));
  const declared = Buffer.from(publicKey.export({ format: 'der', type: 'spki' }));
  try {
    if (!derived.equals(declared)) {
      throw new Error('Activation recovery public and private keys do not match.');
    }
  } finally {
    derived.fill(0);
    declared.fill(0);
  }
}

function encryptActivationRecoveryState(
  state: ActivationRecoveryState,
  protectionSecret: string
): string {
  const salt = randomBytes(16);
  const key = scryptSync(protectionSecret, salt, 32, pendingReceiptScrypt);
  const iv = randomBytes(12);
  const plaintext = Buffer.from(JSON.stringify(state), 'utf8');
  try {
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(activationRecoveryAad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return `${JSON.stringify({
      version: 1,
      kdf: { name: 'scrypt', N: 16_384, r: 8, p: 1 },
      cipher: 'aes-256-gcm',
      salt: salt.toString('base64url'),
      iv: iv.toString('base64url'),
      ciphertext: ciphertext.toString('base64url'),
      authTag: cipher.getAuthTag().toString('base64url')
    }, null, 2)}\n`;
  } finally {
    key.fill(0);
    plaintext.fill(0);
  }
}

async function writeActivationRecoveryState(
  path: string,
  state: ActivationRecoveryState,
  protectionSecret: string,
  replace: boolean
): Promise<void> {
  if (!isAbsolute(path)) throw new Error('Activation recovery path must be absolute.');
  if (!protectionSecret) throw new Error('A non-empty long-term license key is required to protect activation recovery.');
  validateRecoveryIdentity(state);
  const serialized = encryptActivationRecoveryState(state, protectionSecret);
  if (Buffer.byteLength(serialized, 'utf8') > maximumActivationRecoveryBytes) {
    throw new Error('Activation recovery state exceeds the safety limit.');
  }
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  const handle = await open(temporary, 'wx', 0o600);
  let closed = false;
  try {
    await handle.writeFile(serialized, 'utf8');
    await handle.sync();
    await handle.close();
    closed = true;
    if (replace) {
      const metadata = await lstat(path);
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        throw new Error('Activation recovery path is not a regular file.');
      }
      await rename(temporary, path);
    } else {
      await link(temporary, path);
    }
  } finally {
    if (!closed) await handle.close().catch(() => {});
    await rm(temporary, { force: true });
  }
}

async function readActivationRecoveryState(
  path: string,
  protectionSecret: string
): Promise<ActivationRecoveryState> {
  if (!isAbsolute(path)) throw new Error('Activation recovery path must be absolute.');
  const handle = await open(path, 'r');
  let serialized: string;
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > maximumActivationRecoveryBytes) {
      throw new Error('Activation recovery file is empty, oversized, or not a regular file.');
    }
    const bytes = Buffer.alloc(metadata.size);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    const overflow = Buffer.alloc(1);
    const { bytesRead: overflowBytes } = await handle.read(overflow, 0, 1, metadata.size);
    if (bytesRead !== metadata.size || overflowBytes !== 0) {
      throw new Error('Activation recovery file changed while it was being read.');
    }
    serialized = bytes.toString('utf8');
    bytes.fill(0);
  } finally {
    await handle.close();
  }
  const encrypted = encryptedActivationRecoverySchema.parse(JSON.parse(serialized) as unknown);
  const salt = Buffer.from(encrypted.salt, 'base64url');
  const iv = Buffer.from(encrypted.iv, 'base64url');
  const authTag = Buffer.from(encrypted.authTag, 'base64url');
  if (salt.length !== 16 || iv.length !== 12 || authTag.length !== 16) {
    throw new Error('Activation recovery encryption metadata is malformed.');
  }
  const key = scryptSync(protectionSecret, salt, 32, pendingReceiptScrypt);
  let plaintext: Buffer | undefined;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(activationRecoveryAad);
    decipher.setAuthTag(authTag);
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(encrypted.ciphertext, 'base64url')),
      decipher.final()
    ]);
    const state = activationRecoveryStateSchema.parse(JSON.parse(plaintext.toString('utf8')) as unknown);
    validateRecoveryIdentity(state);
    return state;
  } finally {
    key.fill(0);
    plaintext?.fill(0);
  }
}

async function loadOrCreateActivationRecovery(
  options: RetrieveArtifactOptions
): Promise<{ path: string; state: ActivationRecoveryState; created: boolean }> {
  const path = options.activationRecoveryPath ?? `${options.outputPath}.activation.pending.json`;
  if (!isAbsolute(path)) throw new Error('Activation recovery path must be absolute.');
  const expectedServiceUrl = canonicalServiceUrl(options.serviceUrl);
  const expectedSigningKey = signingPublicKeySha256(options.signingPublicKeyPem);
  let state: ActivationRecoveryState;
  let created = false;
  try {
    state = await readActivationRecoveryState(path, options.licenseKey);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    const identity = generateInstallIdentity();
    const now = new Date().toISOString();
    state = activationRecoveryStateSchema.parse({
      version: 1,
      serviceUrl: expectedServiceUrl,
      artifactId: options.artifactId,
      signingPublicKeySha256: expectedSigningKey,
      installId: identity.installId,
      clientPublicKeyPem: identity.publicKeyPem,
      clientPrivateKeyPem: identity.privateKeyPem,
      createdAt: now,
      updatedAt: now
    });
    try {
      await writeActivationRecoveryState(path, state, options.licenseKey, false);
      created = true;
    } catch (writeError) {
      if ((writeError as NodeJS.ErrnoException).code !== 'EEXIST') throw writeError;
      state = await readActivationRecoveryState(path, options.licenseKey);
    }
  }
  if (
    state.serviceUrl !== expectedServiceUrl ||
    state.artifactId !== options.artifactId ||
    state.signingPublicKeySha256 !== expectedSigningKey
  ) {
    throw new Error('Activation recovery state belongs to a different service, artifact, or signing key.');
  }
  return { path, state, created };
}

async function postJson(
  url: URL,
  value: unknown,
  dispatcher?: Dispatcher
): Promise<Record<string, unknown>> {
  const response = await fetchThrough(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify(value),
    redirect: 'error',
    signal: AbortSignal.timeout(30_000)
  }, dispatcher);
  const maximumResponseBytes = 1024 * 1024;
  const chunks: Buffer[] = [];
  let responseBytes = 0;
  if (response.body) {
    for await (const chunk of response.body) {
      const bytes = Buffer.from(chunk);
      responseBytes += bytes.length;
      if (responseBytes > maximumResponseBytes) {
        await response.body.cancel().catch(() => {});
        throw new Error('License service response exceeds the safety limit.');
      }
      chunks.push(bytes);
    }
  }
  const serialized = Buffer.concat(chunks, responseBytes).toString('utf8');
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(serialized) as Record<string, unknown>;
  } catch {
    throw new Error(`License service returned invalid JSON (HTTP ${response.status}).`);
  }
  if (!response.ok) {
    const error = typeof payload.error === 'string' ? payload.error : `HTTP_${response.status}`;
    throw new LicenseServiceRefusalError(error, response.status);
  }
  return payload;
}

function validateActivationArtifact(
  activation: z.infer<typeof activationSchema>,
  options: RetrieveArtifactOptions,
  expectedInstallId: string
): { manifest: ArtifactManifest; manifestSha256: string } {
  if (activation.artifact.id !== options.artifactId) {
    throw new Error('License service returned a different artifact ID.');
  }
  if (activation.envelope.installId !== expectedInstallId) {
    throw new Error('Content-key envelope is bound to a different installation.');
  }
  const manifest: ArtifactManifest = {
    version: 1,
    artifactId: activation.artifact.id,
    downloadUrl: activation.artifact.downloadUrl,
    ciphertextSha256: activation.artifact.ciphertextSha256,
    plaintextSha256: activation.artifact.plaintextSha256
  };
  if (!verifyArtifactManifestSignature(
    manifest,
    activation.artifact.manifestSignature,
    options.signingPublicKeyPem
  )) {
    throw new Error('Artifact manifest signature is invalid.');
  }
  const manifestSha256 = hashArtifactManifest(manifest);
  if (activation.envelope.artifactManifestSha256 !== manifestSha256) {
    throw new Error('Content-key envelope is bound to a different artifact manifest.');
  }
  return { manifest, manifestSha256 };
}

async function downloadArtifact(
  urlValue: string,
  outputPath: string,
  maximumBytes: number,
  dispatcher?: Dispatcher
): Promise<{ bytes: number; sha256: string }> {
  assertApprovedReleaseUrl(urlValue);
  const response = await fetchThrough(urlValue, {
    headers: { 'Accept': 'application/octet-stream' },
    redirect: 'follow',
    signal: AbortSignal.timeout(15 * 60 * 1000)
  }, dispatcher);
  if (!response.ok || !response.body) {
    throw new Error(`Encrypted GitHub Release download failed with HTTP ${response.status}.`);
  }
  assertApprovedReleaseUrl(response.url);
  const declaredLength = Number(response.headers.get('content-length') ?? '0');
  if (declaredLength > maximumBytes) throw new Error('Encrypted artifact exceeds the configured size limit.');

  const hash = createHash('sha256');
  const handle = await open(outputPath, 'wx', 0o600);
  let closed = false;
  let size = 0;
  try {
    for await (const chunk of response.body) {
      const buffer = Buffer.from(chunk);
      size += buffer.length;
      if (size > maximumBytes) throw new Error('Encrypted artifact exceeds the configured size limit.');
      hash.update(buffer);
      let offset = 0;
      while (offset < buffer.length) {
        const { bytesWritten } = await handle.write(buffer, offset, buffer.length - offset, null);
        if (bytesWritten <= 0) throw new Error('Encrypted artifact download could not make forward progress.');
        offset += bytesWritten;
      }
    }
    await handle.sync();
    await handle.close();
    closed = true;
    return { bytes: size, sha256: hash.digest('hex') };
  } catch (error) {
    if (!closed) await handle.close().catch(() => {});
    await rm(outputPath, { force: true }).catch(() => {});
    throw error;
  }
}

async function decryptArtifactToFile(
  encryptedPath: string,
  outputPath: string,
  contentKey: Buffer
): Promise<{ bytes: number; sha256: string }> {
  const handle = await open(encryptedPath, 'r');
  let headerBuffer: Buffer;
  try {
    const metadata = await handle.stat();
    const probeBytes = Math.min(metadata.size, 64);
    headerBuffer = Buffer.alloc(probeBytes);
    const { bytesRead } = await handle.read(headerBuffer, 0, probeBytes, 0);
    if (bytesRead !== probeBytes) throw new Error('Encrypted artifact header could not be read completely.');
  } finally {
    await handle.close();
  }
  const header = parseEncryptedArtifactHeader(headerBuffer);
  headerBuffer.fill(0);
  const decipher = createDecipheriv('aes-256-gcm', contentKey, header.iv);
  decipher.setAAD(encryptedArtifactAad());
  decipher.setAuthTag(header.authTag);
  const hash = createHash('sha256');
  let bytes = 0;
  const meter = new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      bytes += chunk.length;
      hash.update(chunk);
      callback(null, chunk);
    }
  });
  try {
    await pipeline(
      createReadStream(encryptedPath, { start: header.dataOffset }),
      decipher,
      meter,
      createWriteStream(outputPath, { flags: 'wx', mode: 0o600 })
    );
    return { bytes, sha256: hash.digest('hex') };
  } catch (error) {
    await rm(outputPath, { force: true }).catch(() => {});
    throw error;
  }
}

async function sendReceipt(
  serviceUrl: string,
  activationId: string,
  receiptToken: string,
  status: 'DELIVERED' | 'INSTALLED' | 'FAILED',
  dispatcher?: Dispatcher
): Promise<void> {
  await postJson(serviceEndpoint(serviceUrl, 'v1/receipt'), {
    activationId,
    receiptToken,
    status
  }, dispatcher);
}

async function sendReceiptWithRetry(
  serviceUrl: string,
  activationId: string,
  receiptToken: string,
  status: 'DELIVERED' | 'INSTALLED' | 'FAILED',
  dispatcher?: Dispatcher
): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      await sendReceipt(serviceUrl, activationId, receiptToken, status, dispatcher);
      return;
    } catch (error) {
      lastError = error;
      if (attempt < 2) {
        await new Promise((resolveWait) => setTimeout(resolveWait, 250 * (2 ** attempt)));
      }
    }
  }
  throw lastError;
}

async function persistPendingReceipt(args: {
  outputPath: string;
  serviceUrl: string;
  activationId: string;
  receiptToken: string;
  status: 'DELIVERED' | 'INSTALLED' | 'FAILED';
  protectionSecret: string;
  proxyUrl?: string;
}): Promise<string> {
  if (!args.protectionSecret) throw new Error('A non-empty long-term license key is required to protect a pending receipt.');
  const activationReference = sha256(Buffer.from(args.activationId, 'utf8')).slice(0, 32);
  const pendingPath = `${args.outputPath}.receipt-${activationReference}.pending.json`;
  const temporaryPath = `${pendingPath}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  const pending = pendingReceiptSchema.parse({
    version: 1,
    serviceUrl: args.serviceUrl,
    activationId: args.activationId,
    receiptToken: args.receiptToken,
    status: args.status,
    ...(args.proxyUrl ? { proxyUrl: assertApprovedDeliveryProxyUrl(args.proxyUrl).href } : {}),
    createdAt: new Date().toISOString()
  });
  const salt = randomBytes(16);
  const key = scryptSync(args.protectionSecret, salt, 32, pendingReceiptScrypt);
  const iv = randomBytes(12);
  try {
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(pendingReceiptAad);
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(JSON.stringify(pending), 'utf8')),
      cipher.final()
    ]);
    const serialized = `${JSON.stringify({
      version: 1,
      kdf: { name: 'scrypt', N: 16_384, r: 8, p: 1 },
      cipher: 'aes-256-gcm',
      salt: salt.toString('base64url'),
      iv: iv.toString('base64url'),
      ciphertext: ciphertext.toString('base64url'),
      authTag: cipher.getAuthTag().toString('base64url')
    }, null, 2)}\n`;
    const handle = await open(temporaryPath, 'wx', 0o600);
    let closed = false;
    try {
      await handle.writeFile(serialized, 'utf8');
      await handle.sync();
      await handle.close();
      closed = true;
      await link(temporaryPath, pendingPath);
    } finally {
      if (!closed) await handle.close().catch(() => {});
      await rm(temporaryPath, { force: true });
    }
  } finally {
    key.fill(0);
  }
  return pendingPath;
}

async function readPendingReceipt(
  pendingPath: string,
  protectionSecret: string
): Promise<z.infer<typeof pendingReceiptSchema>> {
  const pathMetadata = await lstat(pendingPath);
  if (!pathMetadata.isFile() || pathMetadata.isSymbolicLink()) {
    throw new Error('Pending receipt path must be a regular non-link file.');
  }
  const handle = await open(pendingPath, 'r');
  let serialized: string;
  try {
    const metadata = await handle.stat();
    if (metadata.dev !== pathMetadata.dev || metadata.ino !== pathMetadata.ino) {
      throw new Error('Pending receipt path changed while it was being opened.');
    }
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > maximumPendingReceiptBytes) {
      throw new Error('Pending receipt file is empty, oversized, or not a regular file.');
    }
    const bytes = Buffer.alloc(metadata.size);
    const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    const overflow = Buffer.alloc(1);
    const { bytesRead: overflowBytes } = await handle.read(overflow, 0, 1, metadata.size);
    if (bytesRead !== metadata.size || overflowBytes !== 0) {
      throw new Error('Pending receipt file changed while it was being read.');
    }
    serialized = bytes.toString('utf8');
  } finally {
    await handle.close();
  }
  const encrypted = encryptedPendingReceiptSchema.parse(JSON.parse(serialized) as unknown);
  const salt = Buffer.from(encrypted.salt, 'base64url');
  const iv = Buffer.from(encrypted.iv, 'base64url');
  const authTag = Buffer.from(encrypted.authTag, 'base64url');
  if (salt.length !== 16 || iv.length !== 12 || authTag.length !== 16) {
    throw new Error('Pending receipt encryption metadata is malformed.');
  }
  const key = scryptSync(protectionSecret, salt, 32, pendingReceiptScrypt);
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(pendingReceiptAad);
    decipher.setAuthTag(authTag);
    return pendingReceiptSchema.parse(JSON.parse(Buffer.concat([
      decipher.update(Buffer.from(encrypted.ciphertext, 'base64url')),
      decipher.final()
    ]).toString('utf8')) as unknown);
  } finally {
    key.fill(0);
  }
}

export interface ReconciledReceiptResult {
  status: 'INSTALLED';
  receiptRecorded: boolean;
  receiptPendingPath: string | null;
}

/**
 * Converts a preserved activation recovery record into an INSTALLED receipt.
 * The caller must first verify the exact installed payload, platform marker,
 * bound customer-config hash and (on macOS) active link.
 */
export async function reconcileCompletedActivation(args: {
  activationRecoveryPath: string;
  artifactOutputPath: string;
  licenseKey: string;
  expectedServiceUrl: string;
  expectedArtifactId: string;
  signingPublicKeyPem: string;
  proxyUrl?: string;
}): Promise<ReconciledReceiptResult> {
  if (!isAbsolute(args.activationRecoveryPath) || !isAbsolute(args.artifactOutputPath)) {
    throw new Error('Activation recovery and artifact output paths must be absolute.');
  }
  const state = await readActivationRecoveryState(args.activationRecoveryPath, args.licenseKey);
  if (
    state.serviceUrl !== canonicalServiceUrl(args.expectedServiceUrl)
    || state.artifactId !== args.expectedArtifactId
    || state.signingPublicKeySha256 !== signingPublicKeySha256(args.signingPublicKeyPem)
  ) {
    throw new Error('Activation recovery is bound to a different service, artifact, or delivery signing key.');
  }
  if (!state.activationId || !state.receiptToken) {
    throw new Error('Activation recovery has no issued receipt identity; resume the normal delivery instead.');
  }
  const proxyUrl = args.proxyUrl ? assertApprovedDeliveryProxyUrl(args.proxyUrl).href : undefined;
  const activationReference = sha256(Buffer.from(state.activationId, 'utf8')).slice(0, 32);
  const expectedPendingPath = `${args.artifactOutputPath}.receipt-${activationReference}.pending.json`;
  let pendingPath = expectedPendingPath;
  let pendingCreated = false;
  try {
    await lstat(expectedPendingPath);
    const pending = await readPendingReceipt(expectedPendingPath, args.licenseKey);
    if (
      pending.serviceUrl !== state.serviceUrl
      || pending.activationId !== state.activationId
      || pending.receiptToken !== state.receiptToken
      || pending.status !== 'INSTALLED'
      || pending.proxyUrl !== proxyUrl
    ) {
      throw new Error('Existing pending receipt does not match this completed installation recovery.');
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    pendingPath = await persistPendingReceipt({
      outputPath: args.artifactOutputPath,
      serviceUrl: state.serviceUrl,
      activationId: state.activationId,
      receiptToken: state.receiptToken,
      status: 'INSTALLED',
      protectionSecret: args.licenseKey,
      ...(proxyUrl ? { proxyUrl } : {})
    });
    pendingCreated = true;
  }
  // A newly created encrypted outbox becomes the durable recovery authority.
  // If one pre-existed (for example, power loss between outbox creation and
  // recovery cleanup), retain both until the server confirms the receipt.
  if (pendingCreated) await rm(args.activationRecoveryPath, { force: true });
  const dispatcher = proxyUrl ? deliveryProxyAgent(proxyUrl) : undefined;
  try {
    const receiptRecorded = await sendReceiptWithRetry(
      state.serviceUrl,
      state.activationId,
      state.receiptToken,
      'INSTALLED',
      dispatcher
    ).then(async () => {
      await rm(pendingPath, { force: true }).catch(() => {});
      await rm(args.activationRecoveryPath, { force: true }).catch(() => {});
      return true;
    }, () => false);
    return {
      status: 'INSTALLED',
      receiptRecorded,
      receiptPendingPath: receiptRecorded ? null : pendingPath
    };
  } finally {
    await dispatcher?.close();
  }
}

export interface AbandonedActivationResult {
  status: 'FAILED';
  receiptRecorded: boolean;
  receiptPendingPath: string | null;
}

/**
 * Records an operator-approved terminal abandonment. This is deliberately
 * separate from retrieve/deploy error handling: retryable local or network
 * failures must never call it automatically. The CLI is responsible for
 * proving the configured install target is absent and collecting an explicit
 * typed confirmation from the operator before invoking this function.
 */
export async function abandonActivation(args: {
  activationRecoveryPath: string;
  artifactOutputPath: string;
  licenseKey: string;
  expectedServiceUrl: string;
  expectedArtifactId: string;
  signingPublicKeyPem: string;
  proxyUrl?: string;
}): Promise<AbandonedActivationResult> {
  if (!isAbsolute(args.activationRecoveryPath) || !isAbsolute(args.artifactOutputPath)) {
    throw new Error('Activation recovery and artifact output paths must be absolute.');
  }
  if (!args.licenseKey) throw new Error('A non-empty long-term license key is required to abandon an activation.');
  const state = await readActivationRecoveryState(args.activationRecoveryPath, args.licenseKey);
  if (
    state.serviceUrl !== canonicalServiceUrl(args.expectedServiceUrl)
    || state.artifactId !== args.expectedArtifactId
    || state.signingPublicKeySha256 !== signingPublicKeySha256(args.signingPublicKeyPem)
  ) {
    throw new Error('Activation recovery is bound to a different service, artifact, or delivery signing key.');
  }
  if (!state.activationId || !state.receiptToken) {
    throw new Error('Activation recovery has no issued receipt identity; resume or remove the unissued local recovery record instead.');
  }
  const proxyUrl = args.proxyUrl ? assertApprovedDeliveryProxyUrl(args.proxyUrl).href : undefined;
  const activationReference = sha256(Buffer.from(state.activationId, 'utf8')).slice(0, 32);
  const pendingPath = `${args.artifactOutputPath}.receipt-${activationReference}.pending.json`;
  let pendingCreated = false;
  try {
    await lstat(pendingPath);
    const pending = await readPendingReceipt(pendingPath, args.licenseKey);
    if (
      pending.serviceUrl !== state.serviceUrl
      || pending.activationId !== state.activationId
      || pending.receiptToken !== state.receiptToken
      || pending.status !== 'FAILED'
      || pending.proxyUrl !== proxyUrl
    ) {
      throw new Error('Existing pending receipt does not match this FAILED activation abandonment.');
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    await persistPendingReceipt({
      outputPath: args.artifactOutputPath,
      serviceUrl: state.serviceUrl,
      activationId: state.activationId,
      receiptToken: state.receiptToken,
      status: 'FAILED',
      protectionSecret: args.licenseKey,
      ...(proxyUrl ? { proxyUrl } : {})
    });
    pendingCreated = true;
  }
  // The encrypted outbox is now the durable authority. Do not remove recovery
  // until that outbox exists and has been authenticated above.
  if (pendingCreated) await rm(args.activationRecoveryPath, { force: true });
  const dispatcher = proxyUrl ? deliveryProxyAgent(proxyUrl) : undefined;
  try {
    const receiptRecorded = await sendReceiptWithRetry(
      state.serviceUrl,
      state.activationId,
      state.receiptToken,
      'FAILED',
      dispatcher
    ).then(async () => {
      await rm(pendingPath, { force: true }).catch(() => {});
      await rm(args.activationRecoveryPath, { force: true }).catch(() => {});
      return true;
    }, () => false);
    return {
      status: 'FAILED',
      receiptRecorded,
      receiptPendingPath: receiptRecorded ? null : pendingPath
    };
  } finally {
    await dispatcher?.close();
  }
}

export async function retryPendingReceipt(pendingPath: string, protectionSecret: string): Promise<void> {
  if (!isAbsolute(pendingPath)) throw new Error('Pending receipt path must be absolute.');
  if (!protectionSecret) throw new Error('A non-empty long-term license key is required to unlock the pending receipt.');
  const pending = await readPendingReceipt(pendingPath, protectionSecret);
  const dispatcher = pending.proxyUrl ? deliveryProxyAgent(pending.proxyUrl) : undefined;
  try {
    await sendReceiptWithRetry(
      pending.serviceUrl,
      pending.activationId,
      pending.receiptToken,
      pending.status,
      dispatcher
    );
  } finally {
    await dispatcher?.close();
  }
  await rm(pendingPath, { force: true });
}

async function preflightOutputPath(outputPath: string): Promise<void> {
  if (!isAbsolute(outputPath)) throw new Error('Artifact output path must be absolute.');
  await mkdir(dirname(outputPath), { recursive: true });
  try {
    await lstat(outputPath);
    throw new Error('Artifact output already exists; refusing to overwrite it.');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  const nonce = `${process.pid}.${randomBytes(6).toString('hex')}`;
  const probePath = `${outputPath}.${nonce}.preflight`;
  const probeLinkPath = `${probePath}.link`;
  const handle = await open(probePath, 'wx', 0o600);
  await handle.close();
  try {
    await link(probePath, probeLinkPath);
  } finally {
    await rm(probeLinkPath, { force: true });
    await rm(probePath, { force: true });
  }
}

export async function retrieveArtifact(options: RetrieveArtifactOptions): Promise<RetrieveArtifactResult> {
  let completedStatus: 'DELIVERED' | 'INSTALLED' | undefined;
  let outputCreated = false;
  let recoveryPath: string | undefined;
  let recoveryState: ActivationRecoveryState | undefined;
  const temporaryPath = `${options.outputPath}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  const encryptedTemporaryPath = `${temporaryPath}.encrypted`;
  const dispatcher = options.proxyUrl
    ? deliveryProxyAgent(options.proxyUrl)
    : undefined;
  try {
    await preflightOutputPath(options.outputPath);
    const recovery = await loadOrCreateActivationRecovery(options);
    recoveryPath = recovery.path;
    recoveryState = recovery.state;

    let activationPayload: Record<string, unknown>;
    try {
      activationPayload = await postJson(
        serviceEndpoint(
          options.serviceUrl,
          recoveryState.activationId && recoveryState.recoveryToken
            ? 'v1/activation/resume'
            : 'v1/activate'
        ),
        recoveryState.activationId && recoveryState.recoveryToken
          ? {
            licenseKey: options.licenseKey,
            activationId: recoveryState.activationId,
            recoveryToken: recoveryState.recoveryToken,
            artifactId: options.artifactId,
            installId: recoveryState.installId,
            clientPublicKeyPem: recoveryState.clientPublicKeyPem
          }
          : {
            licenseKey: options.licenseKey,
            oneTimeToken: options.oneTimeToken,
            activationProtocolVersion: 2,
            artifactId: options.artifactId,
            installId: recoveryState.installId,
            clientPublicKeyPem: recoveryState.clientPublicKeyPem
          },
        dispatcher
      );
    } catch (error) {
      // A definite server refusal means no activation was issued. Remove only
      // the brand-new, still-unbound recovery file so a corrected key/token can
      // be entered on the next attempt. Ambiguous network failures preserve it.
      if (
        recovery.created
        && error instanceof LicenseServiceRefusalError
        && isDefiniteNonRetryableActivationRefusal(error)
      ) {
        await rm(recoveryPath, { force: true });
      }
      throw error;
    }
    let activation = activationSchema.parse(activationPayload);
    if (recoveryState.activationId && activation.activationId !== recoveryState.activationId) {
      throw new Error('License service resumed a different activation.');
    }
    if (
      recoveryState.recoveryToken &&
      activation.recoveryToken !== recoveryState.recoveryToken
    ) {
      throw new Error('License service returned a different activation recovery token.');
    }
    let validated = validateActivationArtifact(activation, options, recoveryState.installId);
    recoveryState = activationRecoveryStateSchema.parse({
      ...recoveryState,
      activationId: activation.activationId,
      receiptToken: activation.receiptToken,
      ...(activation.recoveryToken ? { recoveryToken: activation.recoveryToken } : {}),
      updatedAt: new Date().toISOString()
    });
    await writeActivationRecoveryState(recoveryPath, recoveryState, options.licenseKey, true);

    const encrypted = await downloadArtifact(
      activation.artifact.downloadUrl,
      encryptedTemporaryPath,
      options.maximumBytes ?? 2 * 1024 * 1024 * 1024,
      dispatcher
    );
    if (encrypted.sha256 !== activation.artifact.ciphertextSha256) {
      throw new Error('Encrypted artifact SHA-256 does not match the signed delivery record.');
    }

    if (activation.recoveryToken) {
      const renewed = activationSchema.parse(await postJson(
        serviceEndpoint(options.serviceUrl, 'v1/activation/resume'),
        {
          licenseKey: options.licenseKey,
          activationId: activation.activationId,
          recoveryToken: activation.recoveryToken,
          artifactId: options.artifactId,
          installId: recoveryState.installId,
          clientPublicKeyPem: recoveryState.clientPublicKeyPem
        },
        dispatcher
      ));
      if (
        renewed.activationId !== activation.activationId ||
        renewed.receiptToken !== activation.receiptToken ||
        renewed.recoveryToken !== activation.recoveryToken
      ) {
        throw new Error('Renewed activation identity or tokens do not match the original activation.');
      }
      const renewedValidation = validateActivationArtifact(renewed, options, recoveryState.installId);
      if (renewedValidation.manifestSha256 !== validated.manifestSha256) {
        throw new Error('Renewed activation is bound to a different artifact manifest.');
      }
      activation = renewed;
      validated = renewedValidation;
      recoveryState = activationRecoveryStateSchema.parse({
        ...recoveryState,
        receiptToken: renewed.receiptToken,
        recoveryToken: renewed.recoveryToken,
        updatedAt: new Date().toISOString()
      });
      await writeActivationRecoveryState(recoveryPath, recoveryState, options.licenseKey, true);
    }

    const contentKey = unwrapContentKey({
      envelope: activation.envelope as ContentKeyEnvelope,
      expectedArtifactId: options.artifactId,
      expectedArtifactManifestSha256: validated.manifestSha256,
      expectedInstallId: recoveryState.installId,
      clientPrivateKeyPem: recoveryState.clientPrivateKeyPem,
      signingPublicKeyPem: options.signingPublicKeyPem
    });
    let plaintext: { bytes: number; sha256: string };
    try {
      plaintext = await decryptArtifactToFile(encryptedTemporaryPath, temporaryPath, contentKey);
    } finally {
      contentKey.fill(0);
    }
    await rm(encryptedTemporaryPath, { force: true });
    const plaintextHash = plaintext.sha256;
    if (plaintextHash !== activation.artifact.plaintextSha256) {
      await rm(temporaryPath, { force: true });
      throw new Error('Decrypted artifact SHA-256 does not match the delivery record.');
    }

    const plaintextBytes = plaintext.bytes;
    await mkdir(dirname(options.outputPath), { recursive: true });
    await link(temporaryPath, options.outputPath);
    outputCreated = true;
    await rm(temporaryPath, { force: true });
    const artifact: RetrievedArtifact = {
      activationId: activation.activationId,
      artifactId: options.artifactId,
      outputPath: options.outputPath,
      plaintextSha256: plaintextHash,
      bytes: plaintextBytes
    };
    if (options.finalize) await options.finalize(artifact);
    const status = options.finalize ? 'INSTALLED' : 'DELIVERED';
    completedStatus = status;
    // Make the receipt outbox durable before attempting the network call. If
    // power or connectivity fails after installation, the operator still has
    // an idempotent, encrypted receipt to retry.
    const receiptPendingPath = await persistPendingReceipt({
      outputPath: options.outputPath,
      serviceUrl: options.serviceUrl,
      activationId: activation.activationId,
      receiptToken: activation.receiptToken,
      status,
      protectionSecret: options.licenseKey,
      ...(options.proxyUrl ? { proxyUrl: options.proxyUrl } : {})
    });
    await rm(recoveryPath, { force: true });
    const receiptRecorded = await sendReceiptWithRetry(
      options.serviceUrl,
      activation.activationId,
      activation.receiptToken,
      status,
      dispatcher
    ).then(async () => {
      // A stale outbox after a successful receipt is harmless because receipt
      // submission is idempotent; never turn a completed install into failure
      // merely because local cleanup was interrupted.
      await rm(receiptPendingPath, { force: true }).catch(() => {});
      return true;
    }, () => false);
    return {
      ...artifact,
      receiptRecorded,
      receiptPendingPath: receiptRecorded ? null : receiptPendingPath,
      deliveryState: receiptRecorded ? 'RECEIPT_RECORDED' : 'PENDING_RECEIPT',
      status
    };
  } catch (error) {
    if (completedStatus) {
      throw new AggregateError(
        [error],
        `${completedStatus} completed, but its encrypted receipt outbox could not be persisted. Activation recovery was preserved; do not reinstall and use the recovery procedure.`
      );
    }
    const cleanupErrors: unknown[] = [];
    await rm(temporaryPath, { force: true }).catch((cleanupError) => cleanupErrors.push(cleanupError));
    await rm(encryptedTemporaryPath, { force: true }).catch((cleanupError) => cleanupErrors.push(cleanupError));
    if (outputCreated) {
      await rm(options.outputPath, { force: true }).catch((cleanupError) => cleanupErrors.push(cleanupError));
    }
    if (cleanupErrors.length > 0) {
      throw new AggregateError([error, ...cleanupErrors], 'Delivery failed and cleanup also failed.');
    }
    throw error;
  } finally {
    await dispatcher?.close();
  }
}
