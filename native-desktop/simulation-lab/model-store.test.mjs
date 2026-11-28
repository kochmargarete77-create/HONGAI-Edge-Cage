import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { profileDigest } from './model.mjs';
import { createModelStore, openModelStore, readModelStore, updateModelStore } from './model-store.mjs';

const profile = JSON.parse(await fs.readFile(new URL('./fixtures/windows-x64.json', import.meta.url), 'utf8'));
const base = process.env.HONGAI_MODEL_STORE_TEST_ROOT || fileURLToPath(new URL('./tmp/model-store-tests/', import.meta.url));
assert.ok(path.isAbsolute(base));
if (process.platform === 'win32') assert.match(base, /^[DE]:\\/i);
await fs.mkdir(base, { recursive: true });
async function fixture() { return fs.mkdtemp(path.join(base, 'owned-test-')); }
async function newStore() { const directory = await fixture(); await createModelStore(directory, profile); return directory; }

test('create/reopen is idempotent; revision journal and explicit previous snapshot survive reopen', async () => {
  const directory = await fixture();
  const first = await createModelStore(directory, profile);
  const reopened = await openModelStore(directory);
  assert.equal(reopened.modelDigest, profileDigest(profile));
  assert.deepEqual(reopened.profile, first.profile);
  assert.equal(reopened.environmentId, profile.environmentId);
  assert.equal(reopened.previous, null);
  assert.equal((await createModelStore(directory, structuredClone(profile))).changed, false);
  const revision2 = structuredClone(profile); revision2.revision = 2; revision2.hardware.memoryMiB = 32768;
  const updated = await updateModelStore(directory, revision2);
  assert.equal(updated.changed, true); assert.equal(updated.revision, 2);
  assert.equal(updated.previous.revision, 1);
  assert.equal(updated.previous.modelDigest, first.modelDigest);
  assert.equal(JSON.parse(await fs.readFile(path.join(directory, updated.previous.modelFile), 'utf8')).profile.revision, 1);
  const again = await openModelStore(directory);
  assert.equal(again.headDigest, updated.headDigest);
  assert.equal(again.modelDigest, profileDigest(revision2));
  assert.equal(again.recovery.status, 'NONE');
  const journal = JSON.parse(await fs.readFile(path.join(directory, JSON.parse(await fs.readFile(path.join(directory, 'HEAD.json'), 'utf8')).journalFile), 'utf8'));
  assert.equal(journal.previous.modelDigest, first.modelDigest);
});

test('directory boundaries and nonempty unowned customer data are rejected without deletion', async () => {
  await assert.rejects(createModelStore('.', profile), /ABSOLUTE_DIRECTORY/);
  await assert.rejects(createModelStore(path.parse(base).root, profile), /FILESYSTEM_ROOT/);
  const directory = await fixture();
  await fs.writeFile(path.join(directory, 'customer.txt'), 'CUSTOMER_NOT_OWNED');
  await assert.rejects(createModelStore(directory, profile), /NONEMPTY_UNOWNED/);
  assert.equal(await fs.readFile(path.join(directory, 'customer.txt'), 'utf8'), 'CUSTOMER_NOT_OWNED');
  assert.deepEqual(await fs.readdir(directory), ['customer.txt']);
  const link = path.join(await fixture(), 'linked-store');
  await fs.symlink(directory, link, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(createModelStore(link, profile), /LINK/);
});

test('same revision changes, downgrades, and environment changes never replace confirmed data', async () => {
  const directory = await newStore();
  const before = await readModelStore(directory);
  const different = structuredClone(profile); different.hardware.memoryMiB = 32768;
  await assert.rejects(updateModelStore(directory, different), /SAME_REVISION_DIFFERENT_MODEL/);
  const changedIdentity = structuredClone(profile); changedIdentity.environmentId = 'lab-another'; changedIdentity.revision = 2;
  await assert.rejects(updateModelStore(directory, changedIdentity), /ENVIRONMENT_ID_CANNOT_CHANGE/);
  const next = structuredClone(profile); next.revision = 3;
  await updateModelStore(directory, next);
  await assert.rejects(updateModelStore(directory, profile), /REVISION_DOWNGRADE/);
  const stable = await readModelStore(directory);
  assert.equal(stable.revision, 3); assert.equal(stable.previous.modelDigest, before.modelDigest);
});

test('bad JSON, owner corruption and model/journal digest corruption fail without rebuilding', async () => {
  for (const target of ['HEAD.json', 'owner.json', 'model', 'journal']) {
    const directory = await newStore();
    const head = JSON.parse(await fs.readFile(path.join(directory, 'HEAD.json'), 'utf8'));
    const name = target === 'model' ? head.modelFile : target === 'journal' ? head.journalFile : target;
    const file = path.join(directory, name);
    const bad = target === 'model'
      ? Buffer.from((await fs.readFile(file, 'utf8')).replace('16384', '32768'))
      : Buffer.from('{BROKEN_JSON');
    await fs.writeFile(file, bad);
    await assert.rejects(readModelStore(directory), /JSON_INVALID|DIGEST/);
    assert.deepEqual(await fs.readFile(file), bad);
  }
});

test('uncommitted snapshots are retained while reads select only explicitly confirmed HEAD', async () => {
  const directory = await newStore();
  const before = await readModelStore(directory);
  const pending = 'model-r0000000000000002-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json';
  const candidate = structuredClone(profile); candidate.revision = 2;
  await fs.writeFile(path.join(directory, pending), JSON.stringify({ schema: 'hongai.environment-model-snapshot.v1', profile: candidate }));
  await fs.writeFile(path.join(directory, 'customer-project.txt'), 'DO_NOT_DELETE');
  const recovered = await openModelStore(directory);
  assert.equal(recovered.revision, 1); assert.equal(recovered.headDigest, before.headDigest);
  assert.equal(recovered.recovery.status, 'UNCOMMITTED_ARTIFACTS_PRESENT_USING_CONFIRMED_HEAD');
  assert.deepEqual(recovered.recovery.pendingFiles, [pending]);
  assert.equal(recovered.recovery.unknownEntriesCount, 1);
  await updateModelStore(directory, candidate);
  assert.equal((await readModelStore(directory)).revision, 2);
  assert.equal(await fs.readFile(path.join(directory, 'customer-project.txt'), 'utf8'), 'DO_NOT_DELETE');
  assert.equal(JSON.parse(await fs.readFile(path.join(directory, pending), 'utf8')).profile.revision, 2);
});

test('active locks block readers/writers; stale known locks recover without locking forever', async () => {
  const directory = await newStore();
  const lock = path.join(directory, '.model-store.lock');
  const lease = { schema: 'hongai.environment-model-store-lock.v1', directory, pid: process.pid, nonce: 'a'.repeat(32) };
  await fs.writeFile(lock, JSON.stringify(lease));
  await assert.rejects(readModelStore(directory), /BUSY_LIVE_LOCK/);
  await assert.rejects(updateModelStore(directory, { ...profile, revision: 2 }), /BUSY_LIVE_LOCK/);
  assert.equal(JSON.parse(await fs.readFile(lock, 'utf8')).nonce, lease.nonce);
  await fs.unlink(lock); // The test explicitly removes its own synthetic live lease.
  const child = spawn(process.execPath, ['-e', ''], { stdio: 'ignore' });
  await once(child, 'exit');
  await fs.writeFile(lock, JSON.stringify({ ...lease, pid: child.pid }));
  const recovered = await readModelStore(directory);
  assert.equal(recovered.recovery.staleLockRecovered, true);
  assert.equal(recovered.revision, 1);
  assert.equal((await readModelStore(directory)).recovery.staleLockRecovered, false);
  assert.equal((await fs.readdir(directory)).filter((name) => name.startsWith('stale-lock-')).length, 1);
  const unowned = await fixture();
  const unownedLock = path.join(unowned, '.model-store.lock');
  await fs.writeFile(unownedLock, JSON.stringify({ ...lease, directory: unowned, pid: child.pid }));
  const unownedBefore = await fs.readFile(unownedLock);
  await assert.rejects(createModelStore(unowned, profile), /STALE_LOCK_RECOVERY_REQUIRES_VALID_OWNER/);
  assert.deepEqual(await fs.readFile(unownedLock), unownedBefore);
  assert.deepEqual(await fs.readdir(unowned), ['.model-store.lock']);
  await fs.writeFile(lock, 'not-json');
  await assert.rejects(readModelStore(directory), /LOCK_INITIALIZING_OR_INVALID_BUSY/);
  assert.equal(await fs.readFile(lock, 'utf8'), 'not-json');
});

test('concurrent updates produce one committed revision and explicit busy responses', async () => {
  const directory = await newStore();
  const candidate = { ...structuredClone(profile), revision: 2 };
  const results = await Promise.allSettled(Array.from({ length: 6 }, () => updateModelStore(directory, candidate)));
  assert.ok(results.some((result) => result.status === 'fulfilled'));
  for (const result of results) if (result.status === 'rejected') assert.match(result.reason.message, /BUSY|LOCK/);
  const saved = await readModelStore(directory);
  assert.equal(saved.revision, 2); assert.equal(saved.modelDigest, profileDigest(candidate));
  assert.equal(saved.recovery.status, 'NONE');
});

test('model and cumulative owned storage budgets fail without removing history or customer files', async () => {
  const oversized = structuredClone(profile); oversized.hardware.deviceId = 'synthetic-' + 'a'.repeat(66000);
  await assert.rejects(createModelStore(await fixture(), oversized), /MODEL_SIZE_LIMIT_64_KIB|MODEL_TEXT_LIMIT_EXCEEDED|SYNTHETIC_PLACEHOLDER_LABEL_REQUIRED/);
  const longIdentity = structuredClone(profile); longIdentity.environmentId = 'lab-' + 'a'.repeat(9000);
  const longIdentityRoot = await fixture();
  await assert.rejects(createModelStore(longIdentityRoot, longIdentity), /ENVIRONMENT_ID|MODEL_TEXT_LIMIT_EXCEEDED/);
  assert.deepEqual(await fs.readdir(longIdentityRoot), []);
  const directory = await newStore();
  const head = await fs.readFile(path.join(directory, 'HEAD.json'));
  const pending = 'model-r0000000000000002-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json';
  const large = await fs.open(path.join(directory, pending), 'wx');
  await large.truncate(16 * 1024 * 1024); await large.close();
  await assert.rejects(updateModelStore(directory, { ...profile, revision: 2 }), /BUDGET_LIMIT_REACHED/);
  assert.deepEqual(await fs.readFile(path.join(directory, 'HEAD.json')), head);
  assert.equal((await fs.stat(path.join(directory, pending))).size, 16 * 1024 * 1024);
  const countDir = await newStore();
  for (let i = 0; i < 255; i++) {
    const name = `model-r0000000000000002-${i.toString(16).padStart(32, '0')}.json`;
    await fs.writeFile(path.join(countDir, name), '{}');
  }
  await assert.rejects(updateModelStore(countDir, { ...profile, revision: 2 }), /BUDGET_LIMIT_REACHED/);
  assert.equal((await readModelStore(countDir)).revision, 1);
});

test('read size remains bounded when a committed file grows after fstat', async () => {
  const directory = await newStore();
  const head = JSON.parse(await fs.readFile(path.join(directory, 'HEAD.json'), 'utf8'));
  const target = path.join(directory, head.modelFile);
  const builtin = createRequire(import.meta.url)('node:fs/promises');
  const originalOpen = builtin.open;
  let injected = false; let largestBuffer = 0;
  builtin.open = async (...args) => {
    const handle = await originalOpen(...args);
    if (args[0] === target && typeof args[1] === 'number') {
      const originalStat = handle.stat.bind(handle);
      handle.stat = async (...statArgs) => {
        const result = await originalStat(...statArgs);
        if (!injected) {
          injected = true;
          const writer = await originalOpen(target, 'r+');
          await writer.truncate(32 * 1024 * 1024); await writer.close();
        }
        return result;
      };
      const originalRead = handle.read.bind(handle);
      handle.read = async (...readArgs) => {
        largestBuffer = Math.max(largestBuffer, readArgs[0].length);
        return originalRead(...readArgs);
      };
      handle.readFile = async () => { throw new Error('UNBOUNDED_READ_FORBIDDEN_IN_TEST'); };
    }
    return handle;
  };
  syncBuiltinESMExports();
  try {
    await assert.rejects(readModelStore(directory), /FILE_CHANGED_DURING_READ/);
    assert.equal(injected, true);
    assert.ok(largestBuffer > 0 && largestBuffer <= 64 * 1024 + 1);
    assert.equal((await fs.stat(target)).size, 32 * 1024 * 1024);
  } finally { builtin.open = originalOpen; syncBuiltinESMExports(); }
});

test('two independent stale-lock recoverers cannot move the new active lease', async () => {
  const directory = await newStore();
  const departed = spawn(process.execPath, ['-e', ''], { stdio: 'ignore' });
  await once(departed, 'exit');
  await fs.writeFile(path.join(directory, '.model-store.lock'), JSON.stringify({
    schema: 'hongai.environment-model-store-lock.v1', directory, pid: departed.pid, nonce: 'd'.repeat(32),
  }));
  const moduleUrl = new URL('./model-store.mjs', import.meta.url).href;
  const source = `
    import {createRequire,syncBuiltinESMExports} from 'node:module';
    const builtin=createRequire(import.meta.url)('node:fs/promises');
    const originalOpen=builtin.open; let resume; const held=new Promise(r=>resume=r);
    let start; const go=new Promise(r=>start=r); let announced=false;
    process.on('message',m=>{if(m==='go')start();if(m==='release')resume();});
    builtin.open=async(...args)=>{const handle=await originalOpen(...args);
      if(String(args[0]).endsWith('.model-store.lock')&&args[1]==='wx'){
        const sync=handle.sync.bind(handle);handle.sync=async()=>{await sync();
          if(!announced){announced=true;process.send({event:'active'});await held;}};}
      return handle;};
    syncBuiltinESMExports();const {readModelStore}=await import(${JSON.stringify(moduleUrl)});
    process.send({event:'ready'});await go;
    try{const result=await readModelStore(process.argv[1]);process.send({event:'result',ok:true,revision:result.revision});}
    catch(error){process.send({event:'result',ok:false,code:error.message});}
    process.disconnect();`;
  const children = [0, 1].map(() => spawn(process.execPath, ['--input-type=module', '-e', source, directory], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] }));
  const outcomes = []; let ready = 0; let active = null; let holdReleased = false;
  let resolveDone; let rejectDone;
  const done = new Promise((resolve, reject) => { resolveDone = resolve; rejectDone = reject; });
  const releaseIfReady = () => {
    if (!holdReleased && active !== null && outcomes.some((item) => item.index !== active)) {
      holdReleased = true;
      if (children[active].connected) children[active].send('release', () => {});
    }
  };
  for (const [index, child] of children.entries()) {
    child.on('error', rejectDone);
    child.on('message', (message) => {
      if (message.event === 'ready' && ++ready === 2) children.forEach((item) => item.send('go'));
      if (message.event === 'active') { active = index; releaseIfReady(); }
      if (message.event === 'result') { outcomes.push({ index, ...message }); releaseIfReady(); if (outcomes.length === 2) resolveDone(); }
    });
  }
  const timeout = setTimeout(() => rejectDone(new Error('STALE_RECOVERY_CHILD_TIMEOUT')), 9000);
  try {
    await done;
    assert.equal(outcomes.filter((item) => item.ok).length, 1);
    const blocked = outcomes.find((item) => !item.ok);
    assert.match(blocked.code, /BUSY|RECOVERY/);
    assert.equal((await readModelStore(directory)).revision, 1);
    assert.equal((await fs.readdir(directory)).filter((name) => name.startsWith('stale-lock-')).length, 1);
    const recoveryGate = path.join(directory, '.model-store-recovery');
    await fs.mkdir(recoveryGate, { mode: 0o700 });
    await fs.writeFile(path.join(recoveryGate, 'customer-evidence.txt'), 'REVIEW_DO_NOT_REMOVE');
    await assert.rejects(readModelStore(directory), /RECOVERY_BUSY_OR_REVIEW/);
    assert.equal(await fs.readFile(path.join(recoveryGate, 'customer-evidence.txt'), 'utf8'), 'REVIEW_DO_NOT_REMOVE');
  } finally {
    clearTimeout(timeout);
    for (const child of children) { if (child.connected) child.send('release', () => {}); if (child.exitCode === null) child.kill(); }
  }
});
