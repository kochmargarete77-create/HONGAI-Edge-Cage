import { randomUUID } from 'node:crypto';
import { lstat, mkdir, open, readFile, readdir, rm } from 'node:fs/promises';
import { basename, dirname, isAbsolute, resolve } from 'node:path';
import { z } from 'zod';

const ownerSchema = z.object({
  schemaVersion: z.literal(1),
  product: z.literal('HONG AI Edge Cage'),
  pid: z.number().int().positive(),
  nonce: z.string().uuid(),
  startedAt: z.string().datetime({ offset: true })
}).strict();

export interface DeliveryTransactionLock {
  path: string;
  release(): Promise<void>;
}

async function assertPathAbsent(path: string, label: string): Promise<void> {
  try {
    await lstat(path);
    throw new Error(`${label} still exists at ${path}; use the controlled recovery/cleanup flow before recording FAILED.`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

export async function assertNoRecoverableDeliveryResidue(args: {
  artifactOutputPath: string;
  installRoot: string;
  currentLink?: string;
}): Promise<void> {
  await assertPathAbsent(args.artifactOutputPath, 'Decrypted artifact archive');
  await assertPathAbsent(args.installRoot, 'Configured installation root');
  if (args.currentLink) {
    await assertPathAbsent(args.currentLink, 'Configured macOS current link');
    await assertPathAbsent(`${args.currentLink}.previous`, 'Configured macOS previous link');
  }
  const archiveName = basename(args.artifactOutputPath);
  const archiveDirectory = dirname(args.artifactOutputPath);
  const artifactTemporary = new RegExp(
    `^${archiveName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\.[0-9]+\\.[a-f0-9]{12}\\.tmp(?:\\.encrypted)?$`
  );
  const archiveEntries = await readdir(archiveDirectory, { withFileTypes: true }).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return [];
    throw error;
  });
  const archiveResidue = archiveEntries.find((entry) => (
    entry.name.startsWith(`${archiveName}.interrupted-`) || artifactTemporary.test(entry.name)
  ));
  if (archiveResidue) {
    throw new Error(
      `Recoverable decrypted artifact residue still exists at ${resolve(archiveDirectory, archiveResidue.name)}; ` +
      'inspect it and use the controlled secure-cleanup flow before recording FAILED.'
    );
  }

  const installName = basename(args.installRoot);
  const installDirectory = dirname(args.installRoot);
  const installEntries = await readdir(installDirectory, { withFileTypes: true }).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return [];
    throw error;
  });
  const installResidue = installEntries.find((entry) => (
    entry.name.startsWith(`${installName}.failed-`) || entry.name.startsWith(`${installName}.interrupted-`)
  ));
  if (installResidue) {
    throw new Error(
      `Recoverable installation residue still exists at ${resolve(installDirectory, installResidue.name)}; ` +
      'inspect it and use the controlled safe-cleanup flow before recording FAILED.'
    );
  }
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ESRCH') return false;
    if (code === 'EPERM') return true;
    throw error;
  }
}

async function writeOwner(path: string, owner: z.infer<typeof ownerSchema>): Promise<void> {
  const handle = await open(path, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(owner, null, 2)}\n`, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function rejectExistingLock(lockPath: string): Promise<never> {
  const metadata = await lstat(lockPath);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`Delivery transaction lock is not a regular directory: ${lockPath}`);
  }
  const ownerPath = resolve(lockPath, 'owner.json');
  let owner: z.infer<typeof ownerSchema>;
  try {
    const ownerMetadata = await lstat(ownerPath);
    if (!ownerMetadata.isFile() || ownerMetadata.isSymbolicLink()) {
      throw new Error('owner record is not a regular file');
    }
    owner = ownerSchema.parse(JSON.parse(await readFile(ownerPath, 'utf8')) as unknown);
  } catch (error) {
    throw new Error(
      `Delivery transaction lock has no trustworthy owner record; inspect it before removal: ${lockPath}. ` +
      `${error instanceof Error ? error.message : String(error)}`
    );
  }
  if (processIsAlive(owner.pid)) {
    throw new Error(`Another HONG AI delivery/recovery/abandon process (PID ${owner.pid}) owns ${lockPath}.`);
  }
  throw new Error(
    `Delivery lock owner PID ${owner.pid} is no longer running, but an installer child may still be changing WFP, markers, or active links. ` +
    `Automatic lock reclamation is disabled. Fail closed: reboot or prove all child installers have exited, complete the documented platform recovery, ` +
    `then move ${lockPath} into the D:/E: or macOS recovery quarantine before retrying.`
  );
}

export async function acquireDeliveryTransactionLock(artifactOutputPath: string): Promise<DeliveryTransactionLock> {
  if (!isAbsolute(artifactOutputPath)) throw new Error('Artifact output path must be absolute before locking delivery.');
  const outputPath = resolve(artifactOutputPath);
  await mkdir(dirname(outputPath), { recursive: true });
  const lockPath = `${outputPath}.delivery-transaction.lock`;
  const owner = ownerSchema.parse({
    schemaVersion: 1,
    product: 'HONG AI Edge Cage',
    pid: process.pid,
    nonce: randomUUID(),
    startedAt: new Date().toISOString()
  });

  try {
    await mkdir(lockPath, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    return await rejectExistingLock(lockPath);
  }
  try {
    await writeOwner(resolve(lockPath, 'owner.json'), owner);
  } catch (error) {
    await rm(lockPath, { recursive: true, force: true });
    throw error;
  }
  let released = false;
  return {
    path: lockPath,
    release: async () => {
      if (released) return;
      const current = ownerSchema.parse(JSON.parse(
        await readFile(resolve(lockPath, 'owner.json'), 'utf8')
      ) as unknown);
      if (current.nonce !== owner.nonce || current.pid !== owner.pid) {
        throw new Error(`Delivery transaction lock ownership changed; refusing to remove ${lockPath}.`);
      }
      await rm(lockPath, { recursive: true, force: false });
      released = true;
    }
  };
}
