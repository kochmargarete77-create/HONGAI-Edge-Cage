import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
  scryptSync,
  timingSafeEqual
} from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

export interface SecretHash {
  salt: string;
  hash: string;
}

export interface EncryptedSecret {
  iv: string;
  ciphertext: string;
  authTag: string;
}

export interface LicenseAuditEvent {
  id: string;
  sequence: number;
  timestamp: string;
  type: string;
  actorHash: string;
  details: Record<string, string | number | boolean | null>;
  previousHash: string;
  hash: string;
}

export interface LicenseDatabase {
  version: 1;
  artifacts: Array<{
    id: string;
    downloadUrl: string;
    ciphertextSha256: string;
    plaintextSha256: string;
    encryptedContentKey: EncryptedSecret;
    enabled: boolean;
  }>;
  licenses: Array<{
    id: string;
    customerId: string;
    licenseHash: SecretHash;
    allowedArtifacts: string[];
    enabled: boolean;
    createdAt: string;
  }>;
  tokens: Array<{
    id: string;
    licenseId: string;
    tokenHash: SecretHash;
    expiresAt: string;
    usedAt: string | null;
  }>;
  activations: Array<{
    id: string;
    licenseId: string;
    artifactId: string;
    installIdHash: string;
    receiptTokenHash: SecretHash;
    requestedAt: string;
    deliveredAt: string | null;
    completedAt: string | null;
    result: 'KEY_ISSUED' | 'DELIVERED' | 'INSTALLED' | 'FAILED';
  }>;
  events: LicenseAuditEvent[];
}

export function emptyDatabase(): LicenseDatabase {
  return { version: 1, artifacts: [], licenses: [], tokens: [], activations: [], events: [] };
}

export function databasePath(dataRoot: string): string {
  return resolve(dataRoot, 'database.json');
}

export async function readDatabase(dataRoot: string): Promise<LicenseDatabase> {
  try {
    const parsed = JSON.parse(await readFile(databasePath(dataRoot), 'utf8')) as LicenseDatabase;
    parsed.events ??= [];
    for (const activation of parsed.activations) {
      activation.deliveredAt ??= null;
    }
    return parsed;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return emptyDatabase();
    }
    throw error;
  }
}

function auditPayload(event: Omit<LicenseAuditEvent, 'hash'>): string {
  return JSON.stringify(event);
}

export function appendDatabaseEvent(
  database: LicenseDatabase,
  type: string,
  actorHash: string,
  details: LicenseAuditEvent['details']
): LicenseAuditEvent {
  const previous = database.events.at(-1);
  const unsigned: Omit<LicenseAuditEvent, 'hash'> = {
    id: randomUUID(),
    sequence: (previous?.sequence ?? 0) + 1,
    timestamp: new Date().toISOString(),
    type,
    actorHash,
    details,
    previousHash: previous?.hash ?? 'GENESIS'
  };
  const event = {
    ...unsigned,
    hash: createHash('sha256').update(auditPayload(unsigned)).digest('hex')
  };
  database.events.push(event);
  return event;
}

export function verifyDatabaseEvents(events: LicenseAuditEvent[]): boolean {
  let previousHash = 'GENESIS';
  let sequence = 1;
  for (const event of events) {
    const { hash, ...unsigned } = event;
    const expected = createHash('sha256').update(auditPayload(unsigned)).digest('hex');
    if (
      event.sequence !== sequence ||
      event.previousHash !== previousHash ||
      hash !== expected
    ) {
      return false;
    }
    previousHash = hash;
    sequence += 1;
  }
  return true;
}

export async function writeDatabase(dataRoot: string, database: LicenseDatabase): Promise<void> {
  const target = databasePath(dataRoot);
  const temporary = `${target}.${process.pid}.tmp`;
  await mkdir(dirname(target), { recursive: true });
  await writeFile(temporary, `${JSON.stringify(database, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await rename(temporary, target);
}

export function hashSecret(value: string): SecretHash {
  const salt = randomBytes(16);
  const hash = scryptSync(value, salt, 32);
  return { salt: salt.toString('base64url'), hash: hash.toString('base64url') };
}

export function verifySecret(value: string, expected: SecretHash): boolean {
  const actual = scryptSync(value, Buffer.from(expected.salt, 'base64url'), 32);
  const reference = Buffer.from(expected.hash, 'base64url');
  return actual.length === reference.length && timingSafeEqual(actual, reference);
}

export function assertDatabaseAuditChain(database: LicenseDatabase): void {
  if (!verifyDatabaseEvents(database.events)) {
    throw new Error('LICENSE_DATABASE_AUDIT_CHAIN_INVALID');
  }
}

export function encryptAtRest(value: Buffer, masterKey: Buffer): EncryptedSecret {
  if (masterKey.length !== 32) throw new Error('License-service master key must be 32 bytes.');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', masterKey, iv);
  const ciphertext = Buffer.concat([cipher.update(value), cipher.final()]);
  return {
    iv: iv.toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
    authTag: cipher.getAuthTag().toString('base64url')
  };
}

export function decryptAtRest(value: EncryptedSecret, masterKey: Buffer): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', masterKey, Buffer.from(value.iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(value.authTag, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(value.ciphertext, 'base64url')),
    decipher.final()
  ]);
}
