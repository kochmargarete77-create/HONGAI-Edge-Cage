import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import test from 'node:test';
import {
  acquireDeliveryTransactionLock,
  assertNoRecoverableDeliveryResidue
} from '../src/delivery-lock.js';

const projectLocalTemp = resolve('.test-tmp');
const tempParent = process.platform === 'win32' && !/^[DE]:\\/i.test(projectLocalTemp)
  ? 'E:\\codexdata'
  : projectLocalTemp;

async function exitedPid(): Promise<number> {
  return await new Promise<number>((resolvePid, reject) => {
    const child = spawn(process.execPath, ['-e', ''], { stdio: 'ignore', windowsHide: true });
    const pid = child.pid;
    if (!pid) return reject(new Error('test child PID was unavailable'));
    child.once('error', reject);
    child.once('exit', () => resolvePid(pid));
  });
}

test('delivery transaction lock serializes deploy/recovery/abandon callers', async () => {
  await mkdir(tempParent, { recursive: true });
  const root = await mkdtemp(join(tempParent, '_hongai-delivery-lock-'));
  const output = resolve(root, 'artifact.tgz');
  const lock = await acquireDeliveryTransactionLock(output);
  try {
    await assert.rejects(
      acquireDeliveryTransactionLock(output),
      /Another HONG AI delivery\/recovery\/abandon process/
    );
  } finally {
    await lock.release();
  }
  const next = await acquireDeliveryTransactionLock(output);
  await next.release();
  await assert.rejects(stat(`${output}.delivery-transaction.lock`), (error: NodeJS.ErrnoException) => error.code === 'ENOENT');
  await rm(root, { recursive: true, force: true });
});

test('dead parent lock is never reclaimed while a possible orphan installer may still be alive', async () => {
  await mkdir(tempParent, { recursive: true });
  const root = await mkdtemp(join(tempParent, '_hongai-delivery-stale-lock-'));
  const output = resolve(root, 'artifact.tgz');
  const lockPath = `${output}.delivery-transaction.lock`;
  await mkdir(lockPath);
  const possibleOrphan = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
    stdio: 'ignore',
    windowsHide: true
  });
  try {
    await writeFile(resolve(lockPath, 'owner.json'), `${JSON.stringify({
      schemaVersion: 1,
      product: 'HONG AI Edge Cage',
      pid: await exitedPid(),
      nonce: randomUUID(),
      startedAt: new Date().toISOString()
    })}\n`, { mode: 0o600 });
    await assert.rejects(
      acquireDeliveryTransactionLock(output),
      /installer child may still be changing WFP, markers, or active links/
    );
    assert.equal((await stat(lockPath)).isDirectory(), true);
    assert.equal(possibleOrphan.pid ? process.kill(possibleOrphan.pid, 0) : false, true);
  } finally {
    possibleOrphan.kill();
    await rm(root, { recursive: true, force: true });
  }
});

test('FAILED gate rejects plaintext archives, interrupted output and install/link residue', async () => {
  await mkdir(tempParent, { recursive: true });
  const root = await mkdtemp(join(tempParent, '_hongai-delivery-residue-'));
  const artifactOutputPath = resolve(root, 'artifact.tgz');
  const installRoot = resolve(root, 'versions', 'alpha4');
  const currentLink = resolve(root, 'current');
  const clean = { artifactOutputPath, installRoot, currentLink };
  try {
    await assert.doesNotReject(assertNoRecoverableDeliveryResidue(clean));
    await writeFile(artifactOutputPath, 'plaintext archive');
    await assert.rejects(assertNoRecoverableDeliveryResidue(clean), /Decrypted artifact archive still exists/);
    await rm(artifactOutputPath);

    const interruptedArchive = `${artifactOutputPath}.interrupted-${randomUUID()}`;
    await writeFile(interruptedArchive, 'quarantined plaintext archive');
    await assert.rejects(assertNoRecoverableDeliveryResidue(clean), /decrypted artifact residue still exists/i);
    await rm(interruptedArchive);

    const interruptedInstall = `${installRoot}.interrupted-${randomUUID()}`;
    await mkdir(interruptedInstall, { recursive: true });
    await assert.rejects(assertNoRecoverableDeliveryResidue(clean), /installation residue still exists/i);
    await rm(interruptedInstall, { recursive: true });

    await writeFile(`${currentLink}.previous`, 'unexpected active-link residue');
    await assert.rejects(assertNoRecoverableDeliveryResidue(clean), /macOS previous link still exists/);
    await rm(`${currentLink}.previous`);
    await assert.doesNotReject(assertNoRecoverableDeliveryResidue(clean));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
