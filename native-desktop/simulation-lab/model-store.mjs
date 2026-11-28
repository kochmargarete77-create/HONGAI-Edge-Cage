import * as fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { validateModel, profileDigest } from './model.mjs';

const OWNER = 'owner.json';
const HEAD = 'HEAD.json';
const LOCK = '.model-store.lock';
const RECOVERY_GATE = '.model-store-recovery';
const MAX_MODEL_BYTES = 64 * 1024;
const MAX_METADATA_BYTES = 8 * 1024;
const MAX_OWNED_BYTES = 16 * 1024 * 1024;
const MAX_MODEL_FILES = 256;
const MODEL_NAME = /^model-r[0-9]{16}-[a-f0-9]{32}\.json$/;
const JOURNAL_NAME = /^journal-r[0-9]{16}-[a-f0-9]{32}\.json$/;
const TEMP_NAME = /^head-pending-[a-f0-9]{32}\.json$/;
const STALE_NAME = /^stale-lock-[a-f0-9]{32}-[a-f0-9]{32}\.json$/;
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const nonce = () => randomBytes(16).toString('hex');
const fail = (code) => { throw new Error(code); };
const equalPath = (a, b) => typeof a === 'string' && typeof b === 'string'
  && (process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b);
const sameFile = (a, b) => a.dev === b.dev && a.ino === b.ino;
const jsonBytes = (value) => Buffer.from(JSON.stringify(value, null, 2) + '\n', 'utf8');
const ownName = (name) => name === OWNER || name === HEAD || MODEL_NAME.test(name) || JOURNAL_NAME.test(name) || TEMP_NAME.test(name) || STALE_NAME.test(name);

async function checkedDirectory(directory, create = false) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || directory.includes('\0')) fail('STORE_EXPLICIT_ABSOLUTE_DIRECTORY_REQUIRED');
  const full = path.resolve(directory);
  if (equalPath(full, path.parse(full).root)) fail('STORE_FILESYSTEM_ROOT_REJECTED');
  let info;
  try { info = await fs.lstat(full); }
  catch (error) {
    if (error.code !== 'ENOENT' || !create) fail('STORE_DIRECTORY_UNAVAILABLE');
    const parent = path.dirname(full);
    let realParent;
    try { realParent = await fs.realpath(parent); } catch { fail('STORE_PARENT_UNAVAILABLE'); }
    if (!equalPath(realParent, parent)) fail('STORE_LINKED_PARENT_REJECTED');
    try { await fs.mkdir(full, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') fail('STORE_DIRECTORY_CREATE_FAILED'); }
    info = await fs.lstat(full);
  }
  if (!info.isDirectory() || info.isSymbolicLink()) fail('STORE_LINK_OR_NON_DIRECTORY_REJECTED');
  if (!equalPath(await fs.realpath(full), full)) fail('STORE_LINKED_DIRECTORY_REJECTED');
  if (process.platform !== 'win32' && (info.mode & 0o077) !== 0) fail('STORE_DIRECTORY_NOT_PRIVATE');
  return full;
}

async function readRegular(directory, name, maximum = MAX_METADATA_BYTES) {
  if (path.basename(name) !== name || name.includes('\0')) fail('STORE_RELATIVE_LEAF_REQUIRED');
  const target = path.join(directory, name);
  let before;
  try { before = await fs.lstat(target); } catch (error) { if (error.code === 'ENOENT') fail('STORE_REQUIRED_FILE_MISSING'); fail('STORE_FILE_UNREADABLE'); }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > maximum) fail('STORE_FILE_TYPE_OR_SIZE_REJECTED');
  let handle;
  try {
    handle = await fs.open(target, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const opened = await handle.stat();
    if (!sameFile(before, opened) || !opened.isFile() || opened.nlink !== 1 || opened.size > maximum) fail('STORE_FILE_IDENTITY_CHANGED');
    // A writer may grow the file after fstat. Never allocate/read through EOF
    // without a bound; at most maximum+1 bytes are admitted into memory.
    const buffer = Buffer.alloc(maximum + 1);
    let length = 0;
    while (length < buffer.length) {
      const result = await handle.read(buffer, length, buffer.length - length, length);
      if (result.bytesRead === 0) break;
      length += result.bytesRead;
    }
    const bytes = buffer.subarray(0, length);
    if (bytes.length > maximum || bytes.length !== opened.size) fail('STORE_FILE_CHANGED_DURING_READ');
    const after = await fs.lstat(target);
    if (!sameFile(opened, after) || !after.isFile() || after.size !== opened.size) fail('STORE_FILE_IDENTITY_CHANGED');
    return { bytes, info: opened };
  } finally { await handle?.close(); }
}

function parseJson(bytes) {
  try {
    const value = JSON.parse(bytes.toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail('STORE_JSON_OBJECT_REQUIRED');
    return value;
  } catch { fail('STORE_JSON_INVALID_NO_AUTOMATIC_REBUILD'); }
}

async function writeNew(directory, name, bytes) {
  const limit = MODEL_NAME.test(name) ? MAX_MODEL_BYTES : name === 'lease.json' ? 4096 : MAX_METADATA_BYTES;
  if (bytes.length > limit) fail('STORE_ENCODED_FILE_SIZE_LIMIT');
  const target = path.join(directory, name);
  let handle;
  let created;
  let complete = false;
  try {
    handle = await fs.open(target, 'wx', 0o600);
    created = await handle.stat();
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close(); handle = undefined;
    const check = await readRegular(directory, name, limit);
    if (!sameFile(created, check.info) || hash(check.bytes) !== hash(bytes)) fail('STORE_NEW_FILE_VERIFY_FAILED');
    complete = true;
    return { bytes, info: created };
  } catch (error) {
    if (error.code === 'EEXIST') fail('STORE_NEW_FILE_ALREADY_EXISTS_NO_OVERWRITE');
    throw error;
  } finally {
    await handle?.close();
    if (!complete && created) {
      // Only a failed file created by this invocation may be removed.
      try { const now = await fs.lstat(target); if (now.isFile() && sameFile(created, now)) await fs.unlink(target); } catch { /* retain uncertain state for review */ }
    }
  }
}

function validLock(value, directory) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && value.schema === 'hongai.environment-model-store-lock.v1' && equalPath(value.directory || '', directory)
    && Number.isSafeInteger(value.pid) && value.pid > 0 && /^[a-f0-9]{32}$/.test(value.nonce || '');
}

function liveProcess(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) { return error.code !== 'ESRCH'; } // EPERM and unknown errors fail closed.
}

async function assertNoRecoveryGate(directory) {
  try { await fs.lstat(path.join(directory, RECOVERY_GATE)); }
  catch (error) { if (error.code === 'ENOENT') return; fail('STORE_RECOVERY_GATE_UNREADABLE_REVIEW_REQUIRED'); }
  // Gate recovery is deliberately not recursive. A crashed gate needs explicit
  // review; guessing ownership here would recreate the stale-lock race.
  fail('STORE_LOCK_RECOVERY_BUSY_OR_REVIEW_REQUIRED');
}

async function recoverStaleLock(directory) {
  const gate = path.join(directory, RECOVERY_GATE);
  try { await fs.mkdir(gate, { mode: 0o700 }); }
  catch (error) { if (error.code === 'EEXIST') fail('STORE_LOCK_RECOVERY_BUSY_OR_REVIEW_REQUIRED'); fail('STORE_RECOVERY_GATE_CREATE_FAILED'); }
  const gateInfo = await fs.lstat(gate);
  let marker;
  try {
    marker = await writeNew(gate, 'lease.json', jsonBytes({ schema: 'hongai.environment-model-store-recovery.v1', pid: process.pid, nonce: nonce() }));
    // All recoverers take this gate and re-read after acquiring it. A snapshot
    // taken before mkdir must never authorize moving a newly active lease.
    let previous;
    try { previous = await readRegular(directory, LOCK, 4096); }
    catch (error) { if (error.message === 'STORE_REQUIRED_FILE_MISSING') return false; throw error; }
    const lease = parseJson(previous.bytes);
    if (!validLock(lease, directory)) fail('STORE_LOCK_INVALID_REVIEW_REQUIRED');
    if (liveProcess(lease.pid)) fail('STORE_BUSY_LIVE_LOCK');
    try { await readOwner(directory); } catch { fail('STORE_STALE_LOCK_RECOVERY_REQUIRES_VALID_OWNER'); }
    const current = await readRegular(directory, LOCK, 4096);
    const currentLease = parseJson(current.bytes);
    if (!sameFile(previous.info, current.info) || currentLease.nonce !== lease.nonce || liveProcess(currentLease.pid)) fail('STORE_LOCK_CHANGED_RETRY');
    const staleName = `stale-lock-${lease.nonce}-${nonce()}.json`;
    await fs.rename(path.join(directory, LOCK), path.join(directory, staleName));
    const moved = await readRegular(directory, staleName, 4096);
    if (!sameFile(previous.info, moved.info) || parseJson(moved.bytes).nonce !== lease.nonce) fail('STORE_LOCK_RECOVERY_IDENTITY_CHANGED');
    return true;
  } finally {
    // Remove only this invocation's marker and empty gate of the same identity.
    // Unknown contents prevent rmdir and remain for review.
    try {
      const currentGate = await fs.lstat(gate);
      if (currentGate.isDirectory() && !currentGate.isSymbolicLink() && sameFile(gateInfo, currentGate)) {
        if (marker) {
          const currentMarker = await fs.lstat(path.join(gate, 'lease.json'));
          if (currentMarker.isFile() && sameFile(marker.info, currentMarker)) await fs.unlink(path.join(gate, 'lease.json'));
        }
        await fs.rmdir(gate);
      }
    } catch { /* Do not remove an uncertain or nonempty recovery gate. */ }
  }
}

async function lockStore(directory) {
  const record = { schema: 'hongai.environment-model-store-lock.v1', directory, pid: process.pid, nonce: nonce(), createdUtc: new Date().toISOString() };
  const recordBytes = jsonBytes(record);
  if (recordBytes.length > 4096) fail('STORE_LOCK_METADATA_SIZE_LIMIT_4_KIB');
  let staleLockRecovered = false;
  for (let attempt = 0; attempt < 3; attempt++) {
    await assertNoRecoveryGate(directory);
    let handle;
    try {
      handle = await fs.open(path.join(directory, LOCK), 'wx', 0o600);
    } catch (error) {
      if (error.code !== 'EEXIST') fail('STORE_LOCK_CREATE_FAILED');
      let previous;
      try { previous = await readRegular(directory, LOCK, 4096); }
      catch (error) { if (error.message === 'STORE_REQUIRED_FILE_MISSING') continue; fail('STORE_LOCK_UNREADABLE_REVIEW_REQUIRED'); }
      let lease;
      try { lease = JSON.parse(previous.bytes.toString('utf8')); } catch { fail('STORE_LOCK_INITIALIZING_OR_INVALID_BUSY'); }
      if (!validLock(lease, directory)) fail('STORE_LOCK_INVALID_REVIEW_REQUIRED');
      if (liveProcess(lease.pid)) fail('STORE_BUSY_LIVE_LOCK');
      staleLockRecovered = (await recoverStaleLock(directory)) || staleLockRecovered;
      continue;
    }
    let created;
    try {
      created = await handle.stat();
      await handle.writeFile(recordBytes); await handle.sync(); await handle.close(); handle = undefined;
    } catch {
      await handle?.close();
      if (created) {
        try { const now = await fs.lstat(path.join(directory, LOCK)); if (now.isFile() && sameFile(created, now)) await fs.unlink(path.join(directory, LOCK)); }
        catch { /* retain uncertain state for review */ }
      }
      fail('STORE_LOCK_WRITE_FAILED_REVIEW_REQUIRED');
    }
    return {
      staleLockRecovered,
      async assertHeld() {
        const now = await readRegular(directory, LOCK, 4096);
        if (!sameFile(created, now.info) || parseJson(now.bytes).nonce !== record.nonce) fail('STORE_LOCK_OWNERSHIP_LOST');
        await checkedDirectory(directory);
      },
      async release() {
        try { const now = await readRegular(directory, LOCK, 4096); if (sameFile(created, now.info) && parseJson(now.bytes).nonce === record.nonce) await fs.unlink(path.join(directory, LOCK)); }
        catch { /* Never delete an unverified or replaced lease. */ }
      },
    };
  }
  fail('STORE_LOCK_RETRY_LIMIT');
}

async function withLock(directory, create, operation) {
  const full = await checkedDirectory(directory, create);
  const lease = await lockStore(full);
  try { return await operation(full, lease); } finally { await lease.release(); }
}

async function readOwner(directory) {
  const owner = parseJson((await readRegular(directory, OWNER, 8192)).bytes);
  if (owner.schema !== 'hongai.environment-model-store-owner.v1' || !/^store-[a-f0-9]{32}$/.test(owner.storeId || '')
    || !equalPath(owner.directory || '', directory) || !/^lab-[a-z0-9]+(?:-[a-z0-9]+)*$/.test(owner.environmentId || '')) fail('STORE_OWNER_INVALID_NO_AUTOMATIC_REBUILD');
  return owner;
}

function checkedProfile(profile) {
  const normalized = validateModel(profile);
  if (normalized.environmentId.length > 96) fail('STORE_ENVIRONMENT_ID_LENGTH_LIMIT');
  if (jsonBytes(normalized).length > MAX_MODEL_BYTES) fail('STORE_MODEL_SIZE_LIMIT_64_KIB');
  return normalized;
}

function pointer(head) {
  return { revision: head.revision, modelDigest: head.modelDigest, modelFile: head.modelFile, journalFile: head.journalFile, journalDigest: head.journalDigest };
}

function checkPointer(value) {
  if (!value || !Number.isSafeInteger(value.revision) || value.revision < 1 || !/^[a-f0-9]{64}$/.test(value.modelDigest || '')
    || !MODEL_NAME.test(value.modelFile || '') || !JOURNAL_NAME.test(value.journalFile || '') || !/^[a-f0-9]{64}$/.test(value.journalDigest || '')) fail('STORE_HEAD_OR_JOURNAL_POINTER_INVALID');
}

async function scan(directory, committed = new Set()) {
  let ownedBytes = 0; let modelFiles = 0; let unknownEntriesCount = 0;
  let entryCount = 0;
  const pendingFiles = [];
  // opendir's iterator is closed even when a bound/error stops iteration.
  for await (const entry of await fs.opendir(directory)) {
    if (++entryCount > 4096) fail('STORE_DIRECTORY_ENTRY_LIMIT_REVIEW_REQUIRED');
    if (entry.name === LOCK) continue;
    if (!ownName(entry.name)) { unknownEntriesCount++; continue; }
    const info = await fs.lstat(path.join(directory, entry.name));
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) fail('STORE_CONTROLLED_ENTRY_NOT_REGULAR');
    ownedBytes += info.size;
    if (MODEL_NAME.test(entry.name)) modelFiles++;
    if ((MODEL_NAME.test(entry.name) || JOURNAL_NAME.test(entry.name) || TEMP_NAME.test(entry.name)) && !committed.has(entry.name)) pendingFiles.push(entry.name);
  }
  return {
    ownedBytes, maxOwnedBytes: MAX_OWNED_BYTES, modelFiles, maxModelFiles: MAX_MODEL_FILES,
    withinLimit: ownedBytes <= MAX_OWNED_BYTES && modelFiles <= MAX_MODEL_FILES,
    pendingFiles: pendingFiles.sort(), unknownEntriesCount,
  };
}

async function state(directory, lease) {
  const owner = await readOwner(directory);
  const rawHead = await readRegular(directory, HEAD, 8192);
  const head = parseJson(rawHead.bytes);
  checkPointer(head);
  if (head.schema !== 'hongai.environment-model-store-head.v1' || head.storeId !== owner.storeId || head.environmentId !== owner.environmentId) fail('STORE_HEAD_OWNERSHIP_MISMATCH');
  const committed = new Set([HEAD, OWNER]);
  let item = pointer(head); let previous = null; let profile = null; let depth = 0;
  while (item !== null) {
    if (++depth > MAX_MODEL_FILES) fail('STORE_JOURNAL_REVISION_LIMIT');
    checkPointer(item);
    if (committed.has(item.modelFile) || committed.has(item.journalFile)) fail('STORE_JOURNAL_CYCLE_REJECTED');
    const model = parseJson((await readRegular(directory, item.modelFile, MAX_MODEL_BYTES)).bytes);
    const normalized = checkedProfile(model.profile);
    if (model.schema !== 'hongai.environment-model-snapshot.v1' || model.storeId !== owner.storeId || model.environmentId !== owner.environmentId
      || model.revision !== item.revision || normalized.revision !== item.revision || normalized.environmentId !== owner.environmentId
      || model.modelDigest !== item.modelDigest || profileDigest(normalized) !== item.modelDigest) fail('STORE_MODEL_DIGEST_OR_IDENTITY_MISMATCH');
    const journalRaw = await readRegular(directory, item.journalFile, 8192);
    if (hash(journalRaw.bytes) !== item.journalDigest) fail('STORE_JOURNAL_DIGEST_MISMATCH');
    const journal = parseJson(journalRaw.bytes);
    if (journal.schema !== 'hongai.environment-model-revision.v1' || journal.storeId !== owner.storeId || journal.environmentId !== owner.environmentId
      || journal.revision !== item.revision || journal.modelDigest !== item.modelDigest || journal.modelFile !== item.modelFile
      || !['CREATE', 'UPDATE'].includes(journal.operation)) fail('STORE_JOURNAL_IDENTITY_MISMATCH');
    if (journal.previous !== null) {
      checkPointer(journal.previous);
      if (journal.previous.revision >= item.revision || journal.operation !== 'UPDATE') fail('STORE_JOURNAL_REVISION_ORDER_INVALID');
    } else if (journal.operation !== 'CREATE') fail('STORE_JOURNAL_ORIGIN_INVALID');
    if (profile === null) {
      profile = normalized; previous = journal.previous;
      const previousHead = head.previous === null ? null : pointer(head.previous || {});
      if (JSON.stringify(previousHead) !== JSON.stringify(previous)) fail('STORE_PREVIOUS_POINTER_MISMATCH');
    }
    committed.add(item.modelFile); committed.add(item.journalFile);
    item = journal.previous;
  }
  const budget = await scan(directory, committed);
  await lease.assertHeld();
  return {
    directory, environmentId: owner.environmentId, revision: head.revision, modelDigest: head.modelDigest,
    headDigest: hash(rawHead.bytes), profile, previous, powerLossDurabilityVerified: false,
    recovery: {
      status: budget.pendingFiles.length ? 'UNCOMMITTED_ARTIFACTS_PRESENT_USING_CONFIRMED_HEAD' : 'NONE',
      lastConfirmedRevision: head.revision, pendingFiles: budget.pendingFiles,
      unknownEntriesCount: budget.unknownEntriesCount, staleLockRecovered: lease.staleLockRecovered,
    },
    budget,
  };
}

function commitArtifacts(owner, profile, previous) {
  const id = nonce(); const revisionPart = String(profile.revision).padStart(16, '0');
  const modelFile = `model-r${revisionPart}-${id}.json`;
  const journalFile = `journal-r${revisionPart}-${id}.json`;
  const modelDigest = profileDigest(profile);
  const modelBytes = jsonBytes({ schema: 'hongai.environment-model-snapshot.v1', storeId: owner.storeId, environmentId: profile.environmentId, revision: profile.revision, modelDigest, profile });
  const journalBytes = jsonBytes({ schema: 'hongai.environment-model-revision.v1', storeId: owner.storeId, environmentId: profile.environmentId, revision: profile.revision, modelDigest, modelFile, previous, operation: previous ? 'UPDATE' : 'CREATE', createdUtc: new Date().toISOString() });
  const nextHead = { schema: 'hongai.environment-model-store-head.v1', storeId: owner.storeId, environmentId: profile.environmentId, revision: profile.revision, modelDigest, modelFile, journalFile, journalDigest: hash(journalBytes), previous };
  const headBytes = jsonBytes(nextHead);
  if (modelBytes.length > MAX_MODEL_BYTES) fail('STORE_SNAPSHOT_SIZE_LIMIT_64_KIB');
  if (journalBytes.length > MAX_METADATA_BYTES || headBytes.length > MAX_METADATA_BYTES) fail('STORE_COMMIT_METADATA_SIZE_LIMIT_8_KIB');
  return { modelFile, journalFile, modelDigest, modelBytes, journalBytes, headBytes };
}

async function syncDirectory(directory) {
  // Node cannot request directory fsync on Windows. This is not an absolute
  // Windows power-loss durability guarantee; reads still validate every file.
  if (process.platform !== 'win32') {
    const handle = await fs.open(directory, constants.O_RDONLY);
    try { await handle.sync(); } finally { await handle.close(); }
  }
}

async function commit(directory, lease, owner, profile, previousState = null, prepared = null) {
  const previous = previousState ? await readPointer(directory) : null;
  const { modelFile, journalFile, modelDigest, modelBytes, journalBytes, headBytes } = prepared || commitArtifacts(owner, profile, previous);
  const usage = await scan(directory);
  if (usage.modelFiles >= MAX_MODEL_FILES || usage.ownedBytes + modelBytes.length + journalBytes.length + headBytes.length > MAX_OWNED_BYTES) fail('STORE_BUDGET_LIMIT_REACHED_NO_HISTORY_DELETED');
  await lease.assertHeld();
  await writeNew(directory, modelFile, modelBytes);
  await writeNew(directory, journalFile, journalBytes);
  const pendingName = `head-pending-${nonce()}.json`;
  await writeNew(directory, pendingName, headBytes);
  await syncDirectory(directory);
  await lease.assertHeld();
  if (previousState) {
    const current = await readRegular(directory, HEAD, 8192);
    if (hash(current.bytes) !== previousState.headDigest) fail('STORE_HEAD_CHANGED_NO_COMMIT');
  } else {
    try { await fs.lstat(path.join(directory, HEAD)); fail('STORE_HEAD_ALREADY_EXISTS_NO_OVERWRITE'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  // HEAD is the sole commit point. All snapshots/journals already exist and
  // are fsynced; an interruption before this rename keeps the old HEAD valid.
  await fs.rename(path.join(directory, pendingName), path.join(directory, HEAD));
  await syncDirectory(directory);
  const result = await state(directory, lease);
  if (result.modelDigest !== modelDigest || result.revision !== profile.revision) fail('STORE_COMMIT_READBACK_FAILED');
  return { ...result, changed: true };
}

async function readPointer(directory) {
  return pointer(parseJson((await readRegular(directory, HEAD, 8192)).bytes));
}

export async function createModelStore(directory, profile) {
  const normalized = checkedProfile(profile);
  return withLock(directory, true, async (full, lease) => {
    let ownerExists = false;
    try { await fs.lstat(path.join(full, OWNER)); ownerExists = true; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (ownerExists) {
      const current = await state(full, lease);
      if (current.environmentId !== normalized.environmentId) fail('STORE_ENVIRONMENT_ID_CANNOT_CHANGE');
      if (current.revision !== normalized.revision || current.modelDigest !== profileDigest(normalized)) fail('STORE_ALREADY_EXISTS_USE_EXPLICIT_UPDATE');
      return { ...current, changed: false };
    }
    for await (const entry of await fs.opendir(full)) {
      if (entry.name !== LOCK) fail('STORE_NONEMPTY_UNOWNED_DIRECTORY_REJECTED');
    }
    const owner = { schema: 'hongai.environment-model-store-owner.v1', storeId: `store-${nonce()}`, directory: full, environmentId: normalized.environmentId, createdUtc: new Date().toISOString() };
    const ownerBytes = jsonBytes(owner);
    if (ownerBytes.length > MAX_METADATA_BYTES) fail('STORE_OWNER_METADATA_SIZE_LIMIT_8_KIB');
    const prepared = commitArtifacts(owner, normalized, null);
    await lease.assertHeld();
    await writeNew(full, OWNER, ownerBytes);
    return commit(full, lease, owner, normalized, null, prepared);
  });
}

export async function readModelStore(directory) {
  return withLock(directory, false, state);
}

export async function openModelStore(directory) {
  return readModelStore(directory);
}

export async function updateModelStore(directory, profile) {
  const normalized = checkedProfile(profile);
  return withLock(directory, false, async (full, lease) => {
    const current = await state(full, lease);
    if (normalized.environmentId !== current.environmentId) fail('STORE_ENVIRONMENT_ID_CANNOT_CHANGE');
    if (normalized.revision < current.revision) fail('STORE_REVISION_DOWNGRADE_REJECTED');
    if (normalized.revision === current.revision) {
      if (profileDigest(normalized) !== current.modelDigest) fail('STORE_SAME_REVISION_DIFFERENT_MODEL_REJECTED');
      return { ...current, changed: false };
    }
    return commit(full, lease, await readOwner(full), normalized, current);
  });
}
