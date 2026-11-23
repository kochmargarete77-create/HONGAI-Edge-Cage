import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync
} from 'node:crypto';
import { link, lstat, mkdir, open, rm, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute } from 'node:path';
import { z } from 'zod';
import {
  decryptArtifact,
  generateInstallIdentity,
  hashArtifactManifest,
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
  artifact: z.object({
    id: z.string().min(1),
    downloadUrl: z.string().url(),
    ciphertextSha256: z.string().regex(/^[a-f0-9]{64}$/),
    plaintextSha256: z.string().regex(/^[a-f0-9]{64}$/),
    manifestSignature: z.string().min(1)
  }).strict(),
  envelope: envelopeSchema
}).strict();

const pendingReceiptSchema = z.object({
  version: z.literal(1),
  serviceUrl: z.string().url(),
  activationId: z.string().min(1).max(160),
  receiptToken: z.string().min(1).max(256),
  status: z.enum(['DELIVERED', 'INSTALLED', 'FAILED']),
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
const maximumPendingReceiptBytes = 64 * 1024;
const pendingReceiptScrypt = { N: 16_384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 } as const;

export interface RetrieveArtifactOptions {
  serviceUrl: string;
  artifactId: string;
  licenseKey: string;
  oneTimeToken: string;
  signingPublicKeyPem: string;
  outputPath: string;
  maximumBytes?: number;
  finalize?: (artifact: RetrievedArtifact) => Promise<void>;
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

async function postJson(url: URL, value: unknown): Promise<Record<string, unknown>> {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify(value),
    redirect: 'error',
    signal: AbortSignal.timeout(30_000)
  });
  const payload = await response.json() as Record<string, unknown>;
  if (!response.ok) {
    const error = typeof payload.error === 'string' ? payload.error : `HTTP_${response.status}`;
    throw new Error(`License service refused the request: ${error}`);
  }
  return payload;
}

async function downloadArtifact(urlValue: string, maximumBytes: number): Promise<Buffer> {
  assertApprovedReleaseUrl(urlValue);
  const response = await fetch(urlValue, {
    headers: { 'Accept': 'application/octet-stream' },
    redirect: 'follow',
    signal: AbortSignal.timeout(120_000)
  });
  if (!response.ok || !response.body) {
    throw new Error(`Encrypted GitHub Release download failed with HTTP ${response.status}.`);
  }
  assertApprovedReleaseUrl(response.url);
  const declaredLength = Number(response.headers.get('content-length') ?? '0');
  if (declaredLength > maximumBytes) throw new Error('Encrypted artifact exceeds the configured size limit.');

  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of response.body) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > maximumBytes) throw new Error('Encrypted artifact exceeds the configured size limit.');
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

async function sendReceipt(
  serviceUrl: string,
  activationId: string,
  receiptToken: string,
  status: 'DELIVERED' | 'INSTALLED' | 'FAILED'
): Promise<void> {
  await postJson(serviceEndpoint(serviceUrl, 'v1/receipt'), {
    activationId,
    receiptToken,
    status
  });
}

async function sendReceiptWithRetry(
  serviceUrl: string,
  activationId: string,
  receiptToken: string,
  status: 'DELIVERED' | 'INSTALLED' | 'FAILED'
): Promise<void> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      await sendReceipt(serviceUrl, activationId, receiptToken, status);
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

export async function retryPendingReceipt(pendingPath: string, protectionSecret: string): Promise<void> {
  if (!isAbsolute(pendingPath)) throw new Error('Pending receipt path must be absolute.');
  if (!protectionSecret) throw new Error('A non-empty long-term license key is required to unlock the pending receipt.');
  const handle = await open(pendingPath, 'r');
  let serialized: string;
  try {
    const metadata = await handle.stat();
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
  const encrypted = encryptedPendingReceiptSchema.parse(
    JSON.parse(serialized) as unknown
  );
  const salt = Buffer.from(encrypted.salt, 'base64url');
  const iv = Buffer.from(encrypted.iv, 'base64url');
  const authTag = Buffer.from(encrypted.authTag, 'base64url');
  if (salt.length !== 16 || iv.length !== 12 || authTag.length !== 16) {
    throw new Error('Pending receipt encryption metadata is malformed.');
  }
  const key = scryptSync(protectionSecret, salt, 32, pendingReceiptScrypt);
  let pending: z.infer<typeof pendingReceiptSchema>;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(pendingReceiptAad);
    decipher.setAuthTag(authTag);
    pending = pendingReceiptSchema.parse(JSON.parse(Buffer.concat([
      decipher.update(Buffer.from(encrypted.ciphertext, 'base64url')),
      decipher.final()
    ]).toString('utf8')) as unknown);
  } finally {
    key.fill(0);
  }
  await sendReceiptWithRetry(
    pending.serviceUrl,
    pending.activationId,
    pending.receiptToken,
    pending.status
  );
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
  const identity = generateInstallIdentity();
  let activationId: string | undefined;
  let receiptToken: string | undefined;
  let receiptCompleted = false;
  let completedStatus: 'DELIVERED' | 'INSTALLED' | undefined;
  let outputCreated = false;
  const temporaryPath = `${options.outputPath}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  try {
    await preflightOutputPath(options.outputPath);
    const activation = activationSchema.parse(await postJson(
      serviceEndpoint(options.serviceUrl, 'v1/activate'),
      {
        licenseKey: options.licenseKey,
        oneTimeToken: options.oneTimeToken,
        artifactId: options.artifactId,
        installId: identity.installId,
        clientPublicKeyPem: identity.publicKeyPem
      }
    ));
    activationId = activation.activationId;
    receiptToken = activation.receiptToken;
    const currentActivationId = activation.activationId;
    const currentReceiptToken = activation.receiptToken;
    if (activation.artifact.id !== options.artifactId) {
      throw new Error('License service returned a different artifact ID.');
    }
    const artifactManifest: ArtifactManifest = {
      version: 1,
      artifactId: activation.artifact.id,
      downloadUrl: activation.artifact.downloadUrl,
      ciphertextSha256: activation.artifact.ciphertextSha256,
      plaintextSha256: activation.artifact.plaintextSha256
    };
    if (!verifyArtifactManifestSignature(
      artifactManifest,
      activation.artifact.manifestSignature,
      options.signingPublicKeyPem
    )) {
      throw new Error('Artifact manifest signature is invalid.');
    }
    const artifactManifestSha256 = hashArtifactManifest(artifactManifest);
    if (activation.envelope.artifactManifestSha256 !== artifactManifestSha256) {
      throw new Error('Content-key envelope is bound to a different artifact manifest.');
    }

    const encrypted = await downloadArtifact(
      activation.artifact.downloadUrl,
      options.maximumBytes ?? 512 * 1024 * 1024
    );
    if (sha256(encrypted) !== activation.artifact.ciphertextSha256) {
      throw new Error('Encrypted artifact SHA-256 does not match the signed delivery record.');
    }

    const contentKey = unwrapContentKey({
      envelope: activation.envelope as ContentKeyEnvelope,
      expectedArtifactId: options.artifactId,
      expectedArtifactManifestSha256: artifactManifestSha256,
      expectedInstallId: identity.installId,
      clientPrivateKeyPem: identity.privateKeyPem,
      signingPublicKeyPem: options.signingPublicKeyPem
    });
    let plaintext: Buffer;
    try {
      plaintext = decryptArtifact(encrypted, contentKey);
    } finally {
      contentKey.fill(0);
    }
    const plaintextHash = sha256(plaintext);
    if (plaintextHash !== activation.artifact.plaintextSha256) {
      plaintext.fill(0);
      throw new Error('Decrypted artifact SHA-256 does not match the delivery record.');
    }

    const plaintextBytes = plaintext.length;
    await mkdir(dirname(options.outputPath), { recursive: true });
    try {
      await writeFile(temporaryPath, plaintext, { mode: 0o600, flag: 'wx' });
    } finally {
      plaintext.fill(0);
    }
    await link(temporaryPath, options.outputPath);
    outputCreated = true;
    await rm(temporaryPath, { force: true });
    const artifact: RetrievedArtifact = {
      activationId: currentActivationId,
      artifactId: options.artifactId,
      outputPath: options.outputPath,
      plaintextSha256: plaintextHash,
      bytes: plaintextBytes
    };
    if (options.finalize) await options.finalize(artifact);
    const status = options.finalize ? 'INSTALLED' : 'DELIVERED';
    completedStatus = status;
    let receiptPendingPath: string | null = null;
    const receiptRecorded = await sendReceiptWithRetry(
      options.serviceUrl,
      currentActivationId,
      currentReceiptToken,
      status
    ).then(() => true, async () => {
      receiptPendingPath = await persistPendingReceipt({
        outputPath: options.outputPath,
        serviceUrl: options.serviceUrl,
        activationId: currentActivationId,
        receiptToken: currentReceiptToken,
        status,
        protectionSecret: options.licenseKey
      });
      return false;
    });
    receiptCompleted = receiptRecorded;
    return {
      ...artifact,
      receiptRecorded,
      receiptPendingPath,
      deliveryState: receiptRecorded ? 'RECEIPT_RECORDED' : 'PENDING_RECEIPT',
      status
    };
  } catch (error) {
    if (completedStatus) {
      throw new AggregateError(
        [error],
        `${completedStatus} completed, but its receipt could not be recorded or persisted. Do not reinstall; reconcile the activation receipt.`
      );
    }
    const cleanupErrors: unknown[] = [];
    await rm(temporaryPath, { force: true }).catch((cleanupError) => cleanupErrors.push(cleanupError));
    if (outputCreated) {
      await rm(options.outputPath, { force: true }).catch((cleanupError) => cleanupErrors.push(cleanupError));
    }
    if (!receiptCompleted && activationId && receiptToken) {
      const failedActivationId = activationId;
      const failedReceiptToken = receiptToken;
      await sendReceiptWithRetry(options.serviceUrl, failedActivationId, failedReceiptToken, 'FAILED')
        .catch(async (receiptError) => {
          try {
            await persistPendingReceipt({
              outputPath: options.outputPath,
              serviceUrl: options.serviceUrl,
              activationId: failedActivationId,
              receiptToken: failedReceiptToken,
              status: 'FAILED',
              protectionSecret: options.licenseKey
            });
          } catch (pendingError) {
            cleanupErrors.push(new AggregateError([receiptError, pendingError], 'Failure receipt could not be sent or persisted.'));
          }
        });
    }
    if (cleanupErrors.length > 0) {
      throw new AggregateError([error, ...cleanupErrors], 'Delivery failed and cleanup or failure receipt also failed.');
    }
    throw error;
  }
}
