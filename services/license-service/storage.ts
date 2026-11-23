import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
  scryptSync,
  timingSafeEqual
} from 'node:crypto';
import {
  mkdir,
  open,
  readdir,
  readFile,
  rename,
  rmdir,
  stat,
  unlink,
  writeFile
} from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import type { ArtifactManifest } from '../../src/license-protocol.js';

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
    manifest?: ArtifactManifest;
    manifestSignature?: string;
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
    revokedAt: string | null;
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
    for (const token of parsed.tokens) {
      token.revokedAt ??= null;
    }
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

interface DatabaseLockOwner {
  token: string;
  pid: number;
  createdAt: string;
}

function lockDirectory(dataRoot: string): string {
  return resolve(dataRoot, 'database.lock');
}

function processIsAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid < 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

async function reclaimStaleLock(dataRoot: string, staleAfterMs: number): Promise<boolean> {
  const lockPath = lockDirectory(dataRoot);
  let owner: DatabaseLockOwner;
  try {
    owner = JSON.parse(await readFile(resolve(lockPath, 'owner.json'), 'utf8')) as DatabaseLockOwner;
  } catch {
    try {
      const entries = await readdir(lockPath);
      const metadata = await stat(lockPath);
      if (entries.length > 0 || Date.now() - metadata.mtimeMs < staleAfterMs) return false;
      const quarantined = resolve(dataRoot, `database.lock.stale.${randomUUID()}`);
      await rename(lockPath, quarantined);
      await rmdir(quarantined);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true;
      return false;
    }
  }
  const createdAt = Date.parse(owner.createdAt);
  if (!Number.isFinite(createdAt) || Date.now() - createdAt < staleAfterMs || processIsAlive(owner.pid)) {
    return false;
  }

  const quarantined = resolve(dataRoot, `database.lock.stale.${randomUUID()}`);
  try {
    await rename(lockPath, quarantined);
  } catch (error) {
    if (['ENOENT', 'EEXIST'].includes((error as NodeJS.ErrnoException).code ?? '')) return true;
    return false;
  }
  try {
    const quarantinedOwner = JSON.parse(
      await readFile(resolve(quarantined, 'owner.json'), 'utf8')
    ) as DatabaseLockOwner;
    if (quarantinedOwner.token !== owner.token) {
      throw new Error('LICENSE_DATABASE_LOCK_OWNER_CHANGED');
    }
    await unlink(resolve(quarantined, 'owner.json'));
    await rmdir(quarantined);
    return true;
  } catch (error) {
    throw new Error(
      `LICENSE_DATABASE_STALE_LOCK_REQUIRES_MANUAL_REVIEW: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

export async function withDatabaseLock<T>(
  dataRoot: string,
  callback: () => Promise<T> | T,
  options: { timeoutMs?: number; staleAfterMs?: number } = {}
): Promise<T> {
  const timeoutMs = options.timeoutMs ?? 15_000;
  const staleAfterMs = options.staleAfterMs ?? 5 * 60_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1) throw new Error('Invalid database lock timeout.');
  if (!Number.isInteger(staleAfterMs) || staleAfterMs < 1) throw new Error('Invalid stale-lock threshold.');

  await mkdir(dataRoot, { recursive: true });
  const lockPath = lockDirectory(dataRoot);
  const deadline = Date.now() + timeoutMs;
  const owner: DatabaseLockOwner = {
    token: randomUUID(),
    pid: process.pid,
    createdAt: new Date().toISOString()
  };

  while (true) {
    let directoryCreated = false;
    try {
      await mkdir(lockPath);
      directoryCreated = true;
      const handle = await open(resolve(lockPath, 'owner.json'), 'wx', 0o600);
      try {
        await handle.writeFile(`${JSON.stringify(owner)}\n`, 'utf8');
      } finally {
        await handle.close();
      }
      break;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (directoryCreated) {
        try {
          await rmdir(lockPath);
        } catch {
          // A failed acquisition is surfaced below. A leftover directory is never
          // silently reclaimed because its ownership could not be established.
        }
      }
      if (code !== 'EEXIST') throw error;
      if (await reclaimStaleLock(dataRoot, staleAfterMs)) continue;
      if (Date.now() >= deadline) throw new Error('LICENSE_DATABASE_LOCK_TIMEOUT');
      await new Promise((resolveWait) => setTimeout(resolveWait, 50 + Math.floor(Math.random() * 100)));
    }
  }

  try {
    return await callback();
  } finally {
    try {
      const currentOwner = JSON.parse(
        await readFile(resolve(lockPath, 'owner.json'), 'utf8')
      ) as DatabaseLockOwner;
      if (currentOwner.token !== owner.token) throw new Error('LICENSE_DATABASE_LOCK_OWNERSHIP_LOST');
      await unlink(resolve(lockPath, 'owner.json'));
      await rmdir(lockPath);
    } catch (error) {
      throw new Error(
        `LICENSE_DATABASE_LOCK_RELEASE_FAILED: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
}

export async function mutateDatabase<T>(
  dataRoot: string,
  callback: (database: LicenseDatabase) => Promise<T> | T
): Promise<T> {
  return await withDatabaseLock(dataRoot, async () => {
    const database = await readDatabase(dataRoot);
    assertDatabaseAuditChain(database);
    const result = await callback(database);
    await writeDatabase(dataRoot, database);
    return result;
  });
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

export function encryptAtRest(value: Buffer, masterKey: Buffer, additionalData?: Buffer): EncryptedSecret {
  if (masterKey.length !== 32) throw new Error('License-service master key must be 32 bytes.');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', masterKey, iv);
  if (additionalData) cipher.setAAD(additionalData);
  const ciphertext = Buffer.concat([cipher.update(value), cipher.final()]);
  return {
    iv: iv.toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
    authTag: cipher.getAuthTag().toString('base64url')
  };
}

export function decryptAtRest(value: EncryptedSecret, masterKey: Buffer, additionalData?: Buffer): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', masterKey, Buffer.from(value.iv, 'base64url'));
  if (additionalData) decipher.setAAD(additionalData);
  decipher.setAuthTag(Buffer.from(value.authTag, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(value.ciphertext, 'base64url')),
    decipher.final()
  ]);
}
