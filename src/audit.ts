import { createHash, randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import type { CustomerConfig } from './config.js';

export interface AuditEvent {
  sequence: number;
  id: string;
  timestamp: string;
  type: string;
  actor: 'controller' | 'installer' | 'operator' | 'license-service';
  details: unknown;
  previousHash: string;
  hash: string;
}

const pendingWrites = new Map<string, Promise<void>>();
const sensitiveKey = /(password|passwd|secret|token|cookie|authorization|credential|private.?key|license.?key|api.?key)/i;

export function redactSensitive(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(redactSensitive);
  }
  if (value && typeof value === 'object') {
    const redacted: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      redacted[key] = sensitiveKey.test(key) ? '[REDACTED]' : redactSensitive(child);
    }
    return redacted;
  }
  return value;
}

function hashBody(event: Omit<AuditEvent, 'hash'>): string {
  return createHash('sha256').update(JSON.stringify(event)).digest('hex');
}

export function verifyAuditChain(events: AuditEvent[]): boolean {
  let previousHash = 'GENESIS';
  let sequence = 1;
  for (const event of events) {
    const { hash, ...body } = event;
    if (
      event.sequence !== sequence ||
      event.previousHash !== previousHash ||
      hashBody(body) !== hash
    ) {
      return false;
    }
    previousHash = hash;
    sequence += 1;
  }
  return true;
}

export function auditLogPath(config: CustomerConfig): string {
  return resolve(config.workspace.stateRoot, 'controller', 'audit', 'events.jsonl');
}

export async function readAuditEvents(config: CustomerConfig): Promise<AuditEvent[]> {
  const path = auditLogPath(config);
  try {
    const contents = await readFile(path, 'utf8');
    return contents
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => JSON.parse(line) as AuditEvent);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return [];
    }
    throw error;
  }
}

export async function appendAuditEvent(
  config: CustomerConfig,
  type: string,
  actor: AuditEvent['actor'],
  details: unknown
): Promise<AuditEvent> {
  const path = auditLogPath(config);
  let created: AuditEvent | undefined;
  const previous = pendingWrites.get(path) ?? Promise.resolve();
  const current = previous.then(async () => {
    const events = await readAuditEvents(config);
    if (!verifyAuditChain(events)) {
      throw new Error('Audit chain verification failed; refusing to append a new event.');
    }
    const last = events.at(-1);
    const body: Omit<AuditEvent, 'hash'> = {
      sequence: (last?.sequence ?? 0) + 1,
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      type,
      actor,
      details: redactSensitive(details),
      previousHash: last?.hash ?? 'GENESIS'
    };
    created = { ...body, hash: hashBody(body) };
    await mkdir(dirname(path), { recursive: true });
    await appendFile(path, `${JSON.stringify(created)}\n`, { encoding: 'utf8', mode: 0o600 });
  });
  pendingWrites.set(path, current);
  try {
    await current;
    return created as AuditEvent;
  } finally {
    if (pendingWrites.get(path) === current) {
      pendingWrites.delete(path);
    }
  }
}
