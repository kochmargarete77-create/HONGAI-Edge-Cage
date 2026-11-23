import { randomBytes } from 'node:crypto';
import { link, mkdir, rm, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { z } from 'zod';
import {
  decryptArtifact,
  generateInstallIdentity,
  sha256,
  unwrapContentKey,
  type ContentKeyEnvelope
} from './license-protocol.js';

const envelopeSchema = z.object({
  version: z.literal(1),
  artifactId: z.string().min(1),
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
    plaintextSha256: z.string().regex(/^[a-f0-9]{64}$/)
  }).strict(),
  envelope: envelopeSchema
}).strict();

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

export async function retrieveArtifact(options: RetrieveArtifactOptions): Promise<RetrieveArtifactResult> {
  const identity = generateInstallIdentity();
  let activationId: string | undefined;
  let receiptToken: string | undefined;
  let receiptCompleted = false;
  const temporaryPath = `${options.outputPath}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  try {
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
    if (activation.artifact.id !== options.artifactId) {
      throw new Error('License service returned a different artifact ID.');
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
    await writeFile(temporaryPath, plaintext, { mode: 0o600, flag: 'wx' });
    plaintext.fill(0);
    await link(temporaryPath, options.outputPath);
    await rm(temporaryPath, { force: true });
    const artifact: RetrievedArtifact = {
      activationId,
      artifactId: options.artifactId,
      outputPath: options.outputPath,
      plaintextSha256: plaintextHash,
      bytes: plaintextBytes
    };
    if (options.finalize) await options.finalize(artifact);
    const status = options.finalize ? 'INSTALLED' : 'DELIVERED';
    const receiptRecorded = await sendReceipt(
      options.serviceUrl,
      activationId,
      receiptToken,
      status
    ).then(() => true, () => false);
    receiptCompleted = receiptRecorded;
    return {
      ...artifact,
      receiptRecorded,
      status
    };
  } catch (error) {
    await rm(temporaryPath, { force: true }).catch(() => {});
    if (!receiptCompleted && activationId && receiptToken) {
      await sendReceipt(options.serviceUrl, activationId, receiptToken, 'FAILED').catch(() => {});
    }
    throw error;
  }
}
