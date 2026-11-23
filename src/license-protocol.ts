import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  randomUUID,
  sign,
  verify
} from 'node:crypto';

const envelopeInfo = Buffer.from('HONG-AI-EDGE-CAGE-KEY-ENVELOPE-V1', 'utf8');
const artifactMagic = Buffer.from('HAECAGE01', 'ascii');

export interface InstallIdentity {
  installId: string;
  publicKeyPem: string;
  privateKeyPem: string;
}

export interface ContentKeyEnvelope {
  version: 1;
  artifactId: string;
  installId: string;
  issuedAt: string;
  expiresAt: string;
  ephemeralPublicKeyPem: string;
  salt: string;
  iv: string;
  ciphertext: string;
  authTag: string;
  signature: string;
}

type UnsignedEnvelope = Omit<ContentKeyEnvelope, 'signature'>;

export function generateInstallIdentity(): InstallIdentity {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  return {
    installId: randomUUID(),
    publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
  };
}

export function generateSigningKeyPair(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
  };
}

function envelopeBytes(value: UnsignedEnvelope): Buffer {
  return Buffer.from(JSON.stringify(value), 'utf8');
}

function deriveEnvelopeKey(sharedSecret: Buffer, salt: Buffer): Buffer {
  return Buffer.from(hkdfSync('sha256', sharedSecret, salt, envelopeInfo, 32));
}

export function wrapContentKeyForInstall(args: {
  contentKey: Buffer;
  artifactId: string;
  installId: string;
  clientPublicKeyPem: string;
  signingPrivateKeyPem: string;
  ttlSeconds?: number;
}): ContentKeyEnvelope {
  if (args.contentKey.length !== 32) {
    throw new Error('Content key must be exactly 32 bytes.');
  }
  const clientPublicKey = createPublicKey(args.clientPublicKeyPem);
  const { publicKey: ephemeralPublicKey, privateKey: ephemeralPrivateKey } = generateKeyPairSync('x25519');
  const sharedSecret = diffieHellman({ privateKey: ephemeralPrivateKey, publicKey: clientPublicKey });
  const salt = randomBytes(32);
  const wrappingKey = deriveEnvelopeKey(sharedSecret, salt);
  const iv = randomBytes(12);
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + (args.ttlSeconds ?? 300) * 1000);
  const metadata = Buffer.from(`${args.artifactId}\0${args.installId}\0${expiresAt.toISOString()}`, 'utf8');
  const cipher = createCipheriv('aes-256-gcm', wrappingKey, iv);
  cipher.setAAD(metadata);
  const ciphertext = Buffer.concat([cipher.update(args.contentKey), cipher.final()]);
  const unsigned: UnsignedEnvelope = {
    version: 1,
    artifactId: args.artifactId,
    installId: args.installId,
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    ephemeralPublicKeyPem: ephemeralPublicKey.export({ format: 'pem', type: 'spki' }).toString(),
    salt: salt.toString('base64url'),
    iv: iv.toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
    authTag: cipher.getAuthTag().toString('base64url')
  };
  const signature = sign(null, envelopeBytes(unsigned), createPrivateKey(args.signingPrivateKeyPem));
  return { ...unsigned, signature: signature.toString('base64url') };
}

export function unwrapContentKey(args: {
  envelope: ContentKeyEnvelope;
  expectedArtifactId: string;
  expectedInstallId: string;
  clientPrivateKeyPem: string;
  signingPublicKeyPem: string;
  now?: Date;
}): Buffer {
  const { signature, ...unsigned } = args.envelope;
  const signatureValid = verify(
    null,
    envelopeBytes(unsigned),
    createPublicKey(args.signingPublicKeyPem),
    Buffer.from(signature, 'base64url')
  );
  if (!signatureValid) {
    throw new Error('Content-key envelope signature is invalid.');
  }
  if (
    args.envelope.artifactId !== args.expectedArtifactId ||
    args.envelope.installId !== args.expectedInstallId
  ) {
    throw new Error('Content-key envelope is bound to a different artifact or installation.');
  }
  if ((args.now ?? new Date()).getTime() > Date.parse(args.envelope.expiresAt)) {
    throw new Error('Content-key envelope has expired.');
  }
  const sharedSecret = diffieHellman({
    privateKey: createPrivateKey(args.clientPrivateKeyPem),
    publicKey: createPublicKey(args.envelope.ephemeralPublicKeyPem)
  });
  const wrappingKey = deriveEnvelopeKey(sharedSecret, Buffer.from(args.envelope.salt, 'base64url'));
  const metadata = Buffer.from(
    `${args.envelope.artifactId}\0${args.envelope.installId}\0${args.envelope.expiresAt}`,
    'utf8'
  );
  const decipher = createDecipheriv(
    'aes-256-gcm',
    wrappingKey,
    Buffer.from(args.envelope.iv, 'base64url')
  );
  decipher.setAAD(metadata);
  decipher.setAuthTag(Buffer.from(args.envelope.authTag, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(args.envelope.ciphertext, 'base64url')),
    decipher.final()
  ]);
}

export function encryptArtifact(plaintext: Buffer, contentKey: Buffer): Buffer {
  if (contentKey.length !== 32) {
    throw new Error('Content key must be exactly 32 bytes.');
  }
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', contentKey, iv);
  cipher.setAAD(artifactMagic);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([artifactMagic, iv, cipher.getAuthTag(), ciphertext]);
}

export function decryptArtifact(payload: Buffer, contentKey: Buffer): Buffer {
  if (payload.length < artifactMagic.length + 12 + 16) {
    throw new Error('Encrypted artifact is truncated.');
  }
  const magic = payload.subarray(0, artifactMagic.length);
  if (!magic.equals(artifactMagic)) {
    throw new Error('Encrypted artifact header is invalid.');
  }
  const ivStart = artifactMagic.length;
  const tagStart = ivStart + 12;
  const dataStart = tagStart + 16;
  const decipher = createDecipheriv('aes-256-gcm', contentKey, payload.subarray(ivStart, tagStart));
  decipher.setAAD(artifactMagic);
  decipher.setAuthTag(payload.subarray(tagStart, dataStart));
  return Buffer.concat([decipher.update(payload.subarray(dataStart)), decipher.final()]);
}

export function sha256(value: Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}
