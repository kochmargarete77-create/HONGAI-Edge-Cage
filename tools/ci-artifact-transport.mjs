#!/usr/bin/env node

import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  privateDecrypt,
  publicEncrypt,
  randomBytes
} from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { link, lstat, open, readFile, rm } from 'node:fs/promises';
import { basename, dirname, isAbsolute, resolve } from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';

const algorithm = 'RSA-OAEP-SHA256+AES-256-GCM';
const keyWrapLabel = Buffer.from('HONG-AI-CI-ARTIFACT-TRANSPORT-V1', 'utf8');
const maximumBytes = 4 * 1024 * 1024 * 1024;
const maximumRecordBytes = 1024 * 1024;

function fail(message) {
  throw new Error(`HONG AI CI artifact transport: ${message}`);
}

function argument(name) {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function requiredAbsolute(name) {
  const value = argument(name);
  if (!value || !isAbsolute(value)) fail(`--${name} must be an absolute path`);
  return resolve(value);
}

async function regularFile(path, labelName, maximum = maximumBytes) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size <= 0 || metadata.size > maximum) {
    fail(`${labelName} must be a non-empty regular file within the size limit`);
  }
  return metadata;
}

async function mustNotExist(path, labelName) {
  try {
    await lstat(path);
    fail(`${labelName} already exists`);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

function requireDistinctPaths(paths) {
  const normalized = paths.map((path) => process.platform === 'win32' ? path.toLowerCase() : path);
  if (new Set(normalized).size !== normalized.length) {
    fail('input, output, envelope, key, and build-record paths must be distinct');
  }
}

function validFilename(value) {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 255
    && value !== '.'
    && value !== '..'
    && basename(value) === value;
}

async function buildRecord(path) {
  await regularFile(path, 'pilot build record', maximumRecordBytes);
  const serialized = await readFile(path);
  let value;
  try {
    value = JSON.parse(serialized.toString('utf8'));
  } catch {
    fail('pilot build record is not valid JSON');
  }
  if (
    !value
    || typeof value !== 'object'
    || Array.isArray(value)
    || value.schemaVersion !== 1
    || value.product !== 'HONG AI Edge Cage'
    || typeof value.artifactId !== 'string'
    || !value.artifactId
    || !value.archive
    || typeof value.archive !== 'object'
    || !validFilename(value.archive.filename)
    || !Number.isSafeInteger(value.archive.bytes)
    || value.archive.bytes <= 0
    || value.archive.bytes > maximumBytes
    || !/^[a-f0-9]{64}$/.test(value.archive.sha256 ?? '')
    || value.archive.format !== 'tar+gzip'
  ) fail('pilot build record is malformed');
  return {
    value,
    sha256: createHash('sha256').update(serialized).digest('hex')
  };
}

function artifactAad(value) {
  return Buffer.from(JSON.stringify({
    context: 'HONG-AI-CI-ARTIFACT-CONTENT-V1',
    schemaVersion: 1,
    algorithm,
    keyId: value.keyId,
    sourceFilename: value.sourceFilename,
    plaintextBytes: value.plaintextBytes,
    buildRecordSha256: value.buildRecordSha256
  }), 'utf8');
}

function decodeBase64Url(value, labelName) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    fail(`${labelName} is not canonical base64url`);
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length === 0 || decoded.toString('base64url') !== value) {
    fail(`${labelName} is not canonical base64url`);
  }
  return decoded;
}

function keyIdentifier(key) {
  const publicKey = key.type === 'public' ? key : createPublicKey(key);
  if (publicKey.asymmetricKeyType !== 'rsa' || (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 3072) {
    fail('transport key must be RSA with at least 3072 bits');
  }
  return createHash('sha256')
    .update(publicKey.export({ format: 'der', type: 'spki' }))
    .digest('hex');
}

function meter(hash, counter) {
  return new Transform({
    transform(chunk, _encoding, callback) {
      counter.bytes += chunk.length;
      if (counter.bytes > maximumBytes) {
        callback(new Error('artifact exceeds the transport size limit'));
        return;
      }
      hash.update(chunk);
      callback(null, chunk);
    }
  });
}

async function exclusiveJson(path, value) {
  const handle = await open(path, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function fsyncFile(path) {
  const handle = await open(path, 'r+');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function publishExclusive(temporary, output) {
  // A hard link is an atomic no-replace publication on NTFS and APFS. Unlike
  // rename(), it cannot silently overwrite an operator's existing artifact.
  await link(temporary, output);
  await fsyncFile(output);
  await rm(temporary, { force: true });
}

async function encrypt() {
  const input = requiredAbsolute('input');
  const output = requiredAbsolute('output');
  const envelopePath = requiredAbsolute('envelope');
  const publicKeyPath = requiredAbsolute('public-key');
  const buildRecordPath = requiredAbsolute('build-record');
  requireDistinctPaths([input, output, envelopePath, publicKeyPath, buildRecordPath]);
  await mustNotExist(output, 'encrypted output');
  await mustNotExist(envelopePath, 'transport envelope');
  const inputMetadata = await regularFile(input, 'input artifact');
  await regularFile(publicKeyPath, 'public key', 64 * 1024);
  const record = await buildRecord(buildRecordPath);
  if (
    record.value.archive.filename !== basename(input)
    || record.value.archive.bytes !== inputMetadata.size
  ) fail('input artifact does not match the pilot build record filename and size');
  const publicKey = createPublicKey(await readFile(publicKeyPath, 'utf8'));
  const keyId = keyIdentifier(publicKey);
  const contentKey = randomBytes(32);
  const iv = randomBytes(12);
  const plaintextHash = createHash('sha256');
  const ciphertextHash = createHash('sha256');
  const plaintext = { bytes: 0 };
  const ciphertext = { bytes: 0 };
  const temporary = `${output}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  let publishedOutput = false;
  let publishedEnvelope = false;
  try {
    const cipher = createCipheriv('aes-256-gcm', contentKey, iv);
    cipher.setAAD(artifactAad({
      keyId,
      sourceFilename: basename(input),
      plaintextBytes: inputMetadata.size,
      buildRecordSha256: record.sha256
    }));
    await pipeline(
      createReadStream(input),
      meter(plaintextHash, plaintext),
      cipher,
      meter(ciphertextHash, ciphertext),
      createWriteStream(temporary, { flags: 'wx', mode: 0o600 })
    );
    const plaintextSha256 = plaintextHash.digest('hex');
    if (
      plaintext.bytes !== inputMetadata.size
      || plaintext.bytes !== record.value.archive.bytes
      || plaintextSha256 !== record.value.archive.sha256
    ) fail('input artifact content does not match the pilot build record');
    await fsyncFile(temporary);
    await publishExclusive(temporary, output);
    publishedOutput = true;
    const wrappedKey = publicEncrypt({
      key: publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
      oaepLabel: keyWrapLabel
    }, contentKey);
    await exclusiveJson(envelopePath, {
      schemaVersion: 1,
      product: 'HONG AI Edge Cage CI Artifact Transport',
      algorithm,
      keyId,
      sourceFilename: basename(input),
      plaintextBytes: plaintext.bytes,
      plaintextSha256,
      ciphertextBytes: ciphertext.bytes,
      ciphertextSha256: ciphertextHash.digest('hex'),
      buildRecordSha256: record.sha256,
      iv: iv.toString('base64url'),
      authTag: cipher.getAuthTag().toString('base64url'),
      wrappedKey: wrappedKey.toString('base64url')
    });
    publishedEnvelope = true;
    console.log(JSON.stringify({ ok: true, output, envelope: envelopePath, keyId }, null, 2));
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    if (publishedOutput) await rm(output, { force: true }).catch(() => {});
    if (publishedEnvelope) await rm(envelopePath, { force: true }).catch(() => {});
    throw error;
  } finally {
    contentKey.fill(0);
  }
}

function parseEnvelope(value) {
  if (
    !value
    || typeof value !== 'object'
    || Array.isArray(value)
    || value.schemaVersion !== 1
    || value.product !== 'HONG AI Edge Cage CI Artifact Transport'
    || value.algorithm !== algorithm
    || !/^[a-f0-9]{64}$/.test(value.keyId ?? '')
    || !Number.isSafeInteger(value.plaintextBytes)
    || value.plaintextBytes <= 0
    || value.plaintextBytes > maximumBytes
    || !/^[a-f0-9]{64}$/.test(value.plaintextSha256 ?? '')
    || !Number.isSafeInteger(value.ciphertextBytes)
    || value.ciphertextBytes <= 0
    || value.ciphertextBytes > maximumBytes
    || !/^[a-f0-9]{64}$/.test(value.ciphertextSha256 ?? '')
    || !/^[a-f0-9]{64}$/.test(value.buildRecordSha256 ?? '')
    || !validFilename(value.sourceFilename)
    || typeof value.iv !== 'string'
    || typeof value.authTag !== 'string'
    || typeof value.wrappedKey !== 'string'
  ) fail('envelope is malformed');
  return value;
}

async function decrypt() {
  const input = requiredAbsolute('input');
  const output = requiredAbsolute('output');
  const envelopePath = requiredAbsolute('envelope');
  const privateKeyPath = requiredAbsolute('private-key');
  const buildRecordPath = requiredAbsolute('build-record');
  requireDistinctPaths([input, output, envelopePath, privateKeyPath, buildRecordPath]);
  await mustNotExist(output, 'decrypted output');
  const inputMetadata = await regularFile(input, 'encrypted artifact');
  await regularFile(privateKeyPath, 'private key', 64 * 1024);
  const envelopeMetadata = await regularFile(envelopePath, 'transport envelope', 64 * 1024);
  if (inputMetadata.size > maximumBytes || envelopeMetadata.size > 64 * 1024) fail('transport input is oversized');
  const envelope = parseEnvelope(JSON.parse(await readFile(envelopePath, 'utf8')));
  const record = await buildRecord(buildRecordPath);
  if (
    record.sha256 !== envelope.buildRecordSha256
    || record.value.archive.filename !== envelope.sourceFilename
    || record.value.archive.bytes !== envelope.plaintextBytes
    || record.value.archive.sha256 !== envelope.plaintextSha256
  ) fail('pilot build record does not match the authenticated transport envelope');
  if (inputMetadata.size !== envelope.ciphertextBytes) fail('ciphertext size does not match envelope');
  const privateKey = createPrivateKey(await readFile(privateKeyPath, 'utf8'));
  if (keyIdentifier(privateKey) !== envelope.keyId) fail('private key does not match envelope keyId');
  const iv = decodeBase64Url(envelope.iv, 'envelope IV');
  const authTag = decodeBase64Url(envelope.authTag, 'authentication tag');
  if (iv.length !== 12 || authTag.length !== 16) fail('envelope IV or authentication tag is malformed');
  const contentKey = privateDecrypt({
    key: privateKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256',
    oaepLabel: keyWrapLabel
  }, decodeBase64Url(envelope.wrappedKey, 'wrapped content key'));
  if (contentKey.length !== 32) fail('unwrapped content key has the wrong length');
  const temporary = `${output}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  const ciphertextHash = createHash('sha256');
  const plaintextHash = createHash('sha256');
  const ciphertext = { bytes: 0 };
  const plaintext = { bytes: 0 };
  let publishedOutput = false;
  try {
    const decipher = createDecipheriv('aes-256-gcm', contentKey, iv);
    decipher.setAAD(artifactAad(envelope));
    decipher.setAuthTag(authTag);
    await pipeline(
      createReadStream(input),
      meter(ciphertextHash, ciphertext),
      decipher,
      meter(plaintextHash, plaintext),
      createWriteStream(temporary, { flags: 'wx', mode: 0o600 })
    );
    if (
      ciphertext.bytes !== envelope.ciphertextBytes
      || ciphertextHash.digest('hex') !== envelope.ciphertextSha256
      || plaintext.bytes !== envelope.plaintextBytes
      || plaintextHash.digest('hex') !== envelope.plaintextSha256
    ) fail('decrypted artifact size or digest does not match envelope');
    await fsyncFile(temporary);
    await publishExclusive(temporary, output);
    publishedOutput = true;
    console.log(JSON.stringify({
      ok: true,
      output,
      plaintextSha256: envelope.plaintextSha256,
      bytes: envelope.plaintextBytes,
      sourceFilename: envelope.sourceFilename
    }, null, 2));
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    if (publishedOutput) await rm(output, { force: true }).catch(() => {});
    throw error;
  } finally {
    contentKey.fill(0);
  }
}

async function main() {
  const command = process.argv[2];
  if (command === 'encrypt') await encrypt();
  else if (command === 'decrypt') await decrypt();
  else fail('usage: ci-artifact-transport.mjs <encrypt|decrypt> --input ... --output ... --envelope ... --build-record ... --public-key|--private-key ...');
}

main().catch((error) => {
  console.error(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exitCode = 1;
});
